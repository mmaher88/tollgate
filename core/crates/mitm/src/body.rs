//! Response bodies and the small responses the proxy makes itself.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Frame, SizeHint};
use hyper::header::{ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue};
use hyper::{Response, StatusCode};

/// Every body the proxy sends or forwards.
pub(crate) type Body = UnsyncBoxBody<Bytes, hyper::Error>;

pub(crate) fn empty() -> Body {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// An empty response with this status.
pub(crate) fn status(code: StatusCode) -> Response<Body> {
    let mut response = Response::new(empty());
    *response.status_mut() = code;
    response
}

/// The answer to a blocked request: an empty `403` that any origin may read, so pages do
/// not stall on a CORS error.
pub(crate) fn blocked() -> Response<Body> {
    let mut response = status(StatusCode::FORBIDDEN);
    response
        .headers_mut()
        .insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    response
}

/// Wraps a body and runs `on_done` once, when the body ends, fails or is dropped.
pub(crate) struct DoneBody<B> {
    inner: B,
    on_done: Option<Box<dyn FnOnce() + Send>>,
}

impl<B> DoneBody<B> {
    pub(crate) fn new(inner: B, on_done: impl FnOnce() + Send + 'static) -> DoneBody<B> {
        DoneBody {
            inner,
            on_done: Some(Box::new(on_done)),
        }
    }

    fn done(&mut self) {
        if let Some(on_done) = self.on_done.take() {
            on_done();
        }
    }
}

impl<B> Drop for DoneBody<B> {
    fn drop(&mut self) {
        self.done();
    }
}

impl<B> hyper::body::Body for DoneBody<B>
where
    B: hyper::body::Body + Unpin,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(polled, Poll::Ready(None | Some(Err(_)))) {
            self.done();
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
