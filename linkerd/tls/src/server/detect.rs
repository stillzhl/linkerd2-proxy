use super::client_hello;
use crate::ServerId;
use bytes::BytesMut;
use linkerd_detect::Detect;
use linkerd_error::Error;
use linkerd_io::{self as io, AsyncReadExt};
pub use tokio_rustls::server::TlsStream;
use tracing::{debug, trace, warn};

#[derive(Clone, Debug, Default)]
pub struct DetectSni(());

#[async_trait::async_trait]
impl<I> Detect<I> for DetectSni
where
    I: io::AsyncRead + Send + Sync + Unpin,
{
    type Protocol = ServerId;

    async fn detect(
        &self,
        io: &mut I,
        buf: &mut BytesMut,
    ) -> Result<Option<Self::Protocol>, Error> {
        // Peeking didn't return enough data, so instead we'll allocate more
        // capacity and try reading data from the socket.
        debug!("Attempting to buffer TLS ClientHello after incomplete peek");
        debug!(buf.capacity = %buf.capacity(), "Reading bytes from TCP stream");
        while io.read_buf(buf).await? != 0 {
            debug!(buf.len = %buf.len(), "Read bytes from TCP stream");
            match client_hello::parse_sni(buf.as_ref()) {
                Ok(sni) => return Ok(sni),

                Err(client_hello::Incomplete) => {
                    if buf.capacity() == 0 {
                        // If we can't buffer an entire TLS ClientHello, it
                        // almost definitely wasn't initiated by another proxy,
                        // at least.
                        warn!("Buffer insufficient for TLS ClientHello");
                        break;
                    }
                    // Continue if there is still buffer capacity.
                }
            }
        }

        trace!("Could not read TLS ClientHello via buffering");
        Ok(None)
    }
}
