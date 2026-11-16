//! Small bounded DTX transport for an already authenticated RSD tunnel.
//! Protocol layout follows the pinned idevice message implementation.

use anyhow::{bail, Context, Result};
use idevice::dvt::message::{Aux, AuxValue, Message, MessageHeader};
use plist::Value;
use std::collections::HashMap;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};

type Response = oneshot::Sender<Result<Option<Value>>>;
type Command = (i32, String, Vec<AuxValue>, bool, Response);

/// Background reader and dispatcher are aborted when their owner is dropped.
pub struct Dtx {
    commands: mpsc::Sender<Command>,
    pub driver: watch::Receiver<Option<i32>>,
    reader: JoinHandle<()>,
    actor: JoinHandle<Result<()>>,
}

impl Drop for Dtx {
    /// Cancel both halves, including reads interrupted during a partial frame.
    fn drop(&mut self) {
        self.reader.abort();
        self.actor.abort();
    }
}

/// Read a bounded fragmented message before invoking the upstream archive decoder.
async fn read_message(reader: &mut (impl AsyncRead + Unpin)) -> Result<Message> {
    let mut payload = Vec::new();
    let mut identity = None;
    for expected in 0..256u16 {
        let mut header = [0u8; 32];
        reader.read_exact(&mut header).await?;
        let field = |offset| {
            u32::from_le_bytes([
                header[offset],
                header[offset + 1],
                header[offset + 2],
                header[offset + 3],
            ])
        };
        let fragment = u16::from_le_bytes([header[8], header[9]]);
        let count = u16::from_le_bytes([header[10], header[11]]);
        let length = field(12) as usize;
        if field(24) == i32::MIN as u32
            || field(0) != 0x1f3d5b79
            || field(4) != 32
            || count == 0
            || count > 256
            || fragment != expected
        {
            bail!("invalid DTX frame header");
        }
        let signature = (field(16), field(20), field(24), count);
        if identity.is_some_and(|value| value != signature) {
            bail!("interleaved DTX fragments");
        }
        identity = Some(signature);
        // Fragment zero announces the total length without containing bytes.
        if count > 1 && fragment == 0 {
            continue;
        }
        if length > 4 * 1024 * 1024 || payload.len() + length > 4 * 1024 * 1024 {
            bail!("oversized DTX frame");
        }
        let start = payload.len();
        payload.resize(start + length, 0);
        reader.read_exact(&mut payload[start..]).await?;
        if fragment + 1 != count {
            continue;
        }
        if payload.len() < 16 {
            bail!("short DTX payload");
        }
        let aux = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
        let total = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]) as usize;
        if aux > total || total + 16 != payload.len() {
            bail!("invalid DTX payload lengths");
        }
        header[8..10].copy_from_slice(&0u16.to_le_bytes());
        header[10..12].copy_from_slice(&1u16.to_le_bytes());
        header[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        let mut bytes = header.to_vec();
        bytes.extend(payload);
        return Ok(Message::from_reader(&mut bytes.as_slice()).await?);
    }
    bail!("too many DTX fragments")
}

/// Encode a dispatch or reply without fallible archive serialization panics.
fn packet(
    id: u32,
    conversation: u32,
    channel: i32,
    reply: bool,
    kind: u8,
    aux: &[AuxValue],
    data: &[u8],
) -> Vec<u8> {
    let aux = if aux.is_empty() {
        Vec::new()
    } else {
        Aux::from_values(aux.to_vec()).serialize()
    };
    let mut header = MessageHeader::new(0, 1, id, conversation, channel, reply).serialize();
    header[12..16].copy_from_slice(&((16 + aux.len() + data.len()) as u32).to_le_bytes());
    header.extend([kind, 0, 0, 0]);
    header.extend((aux.len() as u32).to_le_bytes());
    header.extend(((aux.len() + data.len()) as u32).to_le_bytes());
    header.extend(0u32.to_le_bytes());
    header.extend(aux);
    header.extend(data);
    header
}

/// Decode the small set of primitive channel metadata values.
fn aux_value(value: &AuxValue) -> Option<Value> {
    match value {
        AuxValue::U32(n) => Some(Value::Integer((*n).into())),
        AuxValue::Array(bytes) => ns_keyed_archive::decode::from_bytes(bytes).ok(),
        AuxValue::String(text) => Some(Value::String(text.clone())),
        _ => None,
    }
}

impl Dtx {
    /// Start independent read and dispatch loops; no partial read is cancelled by a call.
    pub async fn open(stream: impl idevice::ReadWrite + 'static, config: Vec<u8>) -> Result<Self> {
        let (mut read, mut write) = tokio::io::split(stream);
        let (incoming_tx, mut incoming) = mpsc::channel(32);
        let reader = tokio::spawn(async move {
            loop {
                let message = read_message(&mut read).await;
                let failed = message.is_err();
                if incoming_tx.send(message).await.is_err() || failed {
                    break;
                }
            }
        });
        let (commands, mut receive) = mpsc::channel::<Command>(16);
        let (driver_tx, driver) = watch::channel(None);
        let actor = tokio::spawn(async move {
            let mut pending: HashMap<u32, Response> = HashMap::new();
            let mut next = 1u32;
            loop {
                tokio::select! {
                    command = receive.recv() => {
                        let Some((channel, method, args, expects, response)) = command else { return Ok(()); };
                        let data = ns_keyed_archive::encode::encode_to_bytes(Value::String(method))?;
                        let id = next; next = next.checked_add(1).context("DTX identifier exhausted")?;
                        write.write_all(&packet(id, 0, channel, expects, 2, &args, &data)).await?;
                        if expects { pending.insert(id, response); } else { let _ = response.send(Ok(None)); }
                    }
                    received = incoming.recv() => {
                        let message = received.context("DTX reader closed")??;
                        let header = message.message_header.serialize();
                        let field = |offset| u32::from_le_bytes([header[offset],header[offset+1],header[offset+2],header[offset+3]]);
                        let id = field(16); let conversation = field(20);
                        next = next.max(id.saturating_add(1));
                        if conversation % 2 == 1 {
                            if let Some(response) = pending.remove(&id) {
                                let error = message.payload_header.serialize()[0] == 4;
                                let _ = response.send(if error { Err(anyhow::anyhow!("DTX service rejected the request")) } else { Ok(message.data) });
                            }
                            continue;
                        }
                        let method = message.data.as_ref().and_then(Value::as_string).unwrap_or("");
                        let mut bytes = Vec::new();
                        if method == "_requestChannelWithCode:identifier:" {
                            let args = message.aux.as_ref().context("missing reverse channel arguments")?;
                            let code = args.values.first().and_then(aux_value).and_then(|v| v.as_unsigned_integer()).context("invalid reverse channel code")?;
                            let identifier = args.values.get(1).and_then(aux_value).context("missing reverse channel identifier")?;
                            if identifier.as_string().is_some_and(|name| name.contains("XCTestDriverInterface")) && code <= i32::MAX as u64 {
                                let _ = driver_tx.send(Some(-(code as i32)));
                            }
                        } else if method == "_XCT_testRunnerReadyWithCapabilities:" {
                            bytes.clone_from(&config);
                        } else if method == "_XCT_exchangeCurrentProtocolVersion_minimumVersion_" {
                            bytes = ns_keyed_archive::encode::encode_to_bytes(Value::Integer(36.into()))?;
                        } else if matches!(method, "_XCT_logMessage:" | "_XCT_logDebugMessage:") {
                            let revoked = message.aux.as_ref().is_some_and(|aux| aux.values.iter().filter_map(aux_value)
                                .any(|value| value.as_string().is_some_and(|text| text.contains("Not authorized for performing UI testing actions"))));
                            if revoked { eprintln!("Not authorized for performing UI testing actions"); bail!("wireless UI automation revoked"); }
                        } else if matches!(method, "_XCT_didFinishExecutingTestPlan" | "_XCT_didFailToBootstrapWithError:" | "_XCT_initializationForUITestingDidFailWithError:") {
                            // Keep the safe terminal marker even when a pending call is
                            // dropped before its caller can observe the actor's error.
                            eprintln!("wireless XCTest ended: {method}");
                            for (_, response) in pending.drain() {
                                let _ = response.send(Err(anyhow::anyhow!("wireless XCTest ended: {method}")));
                            }
                            bail!("wireless XCTest ended: {method}");
                        }
                        if field(28) == 1 {
                            let channel = -message.message_header.channel;
                            write.write_all(&packet(id, conversation+1, channel, false, if bytes.is_empty() {0} else {3}, &[], &bytes)).await?;
                        }
                    }
                }
            }
        });
        let connection = Self {
            commands,
            driver,
            reader,
            actor,
        };
        let caps = super::dict!(dict { "com.apple.private.DTXBlockCompression": 0i64, "com.apple.private.DTXConnection": 1i64 });
        connection
            .call(
                0,
                "_notifyOfPublishedCapabilities:",
                vec![AuxValue::archived_value(Value::Dictionary(caps))],
                false,
            )
            .await?;
        Ok(connection)
    }

    /// Correlate a method reply while the dispatcher continues servicing callbacks.
    pub async fn call(
        &self,
        channel: i32,
        method: &str,
        args: Vec<AuxValue>,
        reply: bool,
    ) -> Result<Option<Value>> {
        let (send, receive) = oneshot::channel();
        self.commands
            .send((channel, method.into(), args, reply, send))
            .await
            .map_err(|_| anyhow::anyhow!("DTX disconnected"))?;
        tokio::time::timeout(std::time::Duration::from_secs(30), receive)
            .await?
            .map_err(|_| anyhow::anyhow!("DTX reply sender closed"))?
    }

    /// Request a named service channel on the root connection.
    pub async fn channel(&self, name: &str) -> Result<i32> {
        self.call(
            0,
            "_requestChannelWithCode:identifier:",
            vec![
                AuxValue::U32(1),
                AuxValue::archived_value(Value::String(name.into())),
            ],
            true,
        )
        .await?;
        Ok(1)
    }

    /// Wait for a transport or remote XCTest failure.
    pub async fn finished(&mut self) -> Result<()> {
        (&mut self.actor).await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A remote test-plan finish remains explicit while a method reply is pending.
    #[test]
    fn terminal_callback_preserves_pending_call_error() -> Result<()> {
        crate::setup::sys::block_on(async {
            let (client, mut server) = tokio::io::duplex(16384);
            let connection = Dtx::open(client, Vec::new()).await?;
            let remote = tokio::spawn(async move {
                let _capabilities = read_message(&mut server).await?;
                let _request = read_message(&mut server).await?;
                let method = ns_keyed_archive::encode::encode_to_bytes(Value::String(
                    "_XCT_didFinishExecutingTestPlan".into(),
                ))?;
                server
                    .write_all(&packet(101, 0, 0, false, 2, &[], &method))
                    .await?;
                Ok::<_, anyhow::Error>(())
            });
            let result = connection.call(1, "pending", vec![], true).await;
            assert!(result.is_err_and(|error| error
                .to_string()
                .contains("wireless XCTest ended: _XCT_didFinishExecutingTestPlan")));
            remote.await??;
            Ok(())
        })
    }

    /// Reject malformed lengths before the upstream decoder can index a short payload.
    #[test]
    fn rejects_short_and_oversized_frames() -> Result<()> {
        crate::setup::sys::block_on(async {
            let mut bytes = packet(1, 0, 0, false, 2, &[], &[]);
            bytes[12..16].copy_from_slice(&8u32.to_le_bytes());
            assert!(read_message(&mut bytes.as_slice()).await.is_err());
            bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(read_message(&mut bytes.as_slice()).await.is_err());
            Ok(())
        })
    }

    /// Reverse channel and configuration callbacks must be serviced during a pending call.
    #[test]
    fn callbacks_do_not_block_correlated_replies() -> Result<()> {
        crate::setup::sys::block_on(async {
            let (client, mut server) = tokio::io::duplex(16384);
            let config =
                ns_keyed_archive::encode::encode_to_bytes(Value::String("test-config".into()))?;
            let connection = Dtx::open(client, config).await?;
            let remote = tokio::spawn(async move {
                let _capabilities = read_message(&mut server).await?;
                let request = read_message(&mut server).await?;
                let header = request.message_header.serialize();
                let id = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
                let selector = ns_keyed_archive::encode::encode_to_bytes(Value::String(
                    "_requestChannelWithCode:identifier:".into(),
                ))?;
                let args = [
                    AuxValue::U32(7),
                    AuxValue::archived_value(Value::String(
                        "dtxproxy:XCTestManager_IDEInterface:XCTestDriverInterface".into(),
                    )),
                ];
                server
                    .write_all(&packet(101, 0, 0, true, 2, &args, &selector))
                    .await?;
                let _ack = read_message(&mut server).await?;
                let selector = ns_keyed_archive::encode::encode_to_bytes(Value::String(
                    "_XCT_testRunnerReadyWithCapabilities:".into(),
                ))?;
                server
                    .write_all(&packet(102, 0, 7, true, 2, &[], &selector))
                    .await?;
                let reply = read_message(&mut server).await?;
                assert_eq!(reply.data, Some(Value::String("test-config".into())));
                server
                    .write_all(&packet(id, 1, 1, false, 0, &[], &[]))
                    .await?;
                Ok::<_, anyhow::Error>(())
            });
            connection.call(1, "pending", vec![], true).await?;
            assert_eq!(*connection.driver.borrow(), Some(-7));
            remote.await??;
            Ok(())
        })
    }
}
