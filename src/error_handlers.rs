use actix_web::{HttpResponse, HttpRequest, Result};
use actix_session::Session;

use crate::templates::*;

// 404 handler
pub async fn error_404(req: HttpRequest, s: Session) -> Result<HttpResponse> {
    let l = get_lang(&req);

    let tpl = TplNotification::new("home", "error_404", false, &l);
    return HttpResponse::NotFound().content_type("text/html").body(
        gentpl_home(&l, &s, None, Some(tpl))
    ).await;
    
}

