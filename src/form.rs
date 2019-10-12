// General input checking is implemented here.

// url uses
use url::Url;

// rocket uses
use rocket::http::RawStr;
use rocket::request::FromFormValue;

// Form structure. The following fields must be present.
#[derive(FromForm, Serialize, Clone, Debug)]
pub struct LinksForm {
    pub url_from: Option<InputUrlCustomText>,
    pub url_to: Option<InputUrl>,
    pub captcha: Option<InputCaptcha>,
}

// used to remove all of this Option<> crap
pub struct ValidLink {
    pub url_from: InputUrlCustomText,
    pub url_to: InputUrl,
    pub captcha: InputCaptcha,
}

// converting a LinksForm to a ValidLink
impl LinksForm {
    pub fn is_valid(&self) -> Option<ValidLink> {
        Some(ValidLink {
            url_from: self.url_from.clone()?,
            url_to: self.url_to.clone()?,
            captcha: self.captcha.clone()?,
        })
    }
}

#[derive(Serialize, PartialEq, Debug, Clone)]
pub struct InputUrlCustomText(pub String);

#[derive(Serialize, PartialEq, Debug, Clone)]
pub struct InputUrl(pub String);

#[derive(Serialize, PartialEq, Debug, Clone)]
pub struct InputCaptcha(pub String);

// url_from Form value
// url_from is the custom text set for the link.
// A valid url_from value must have between 0 and 80 characters.
impl<'v> FromFormValue<'v> for InputUrlCustomText {

    type Error = &'v RawStr;
    fn from_form_value(form_value: &'v RawStr) -> Result<InputUrlCustomText, &'v RawStr> {
        match form_value.trim().url_decode_lossy().len() <= 50 {
            true => Ok(InputUrlCustomText(form_value.trim().url_decode_lossy())),
            false => Err(form_value),
        }
    }
}

// url_to Form value
// url_to is the URL users gets redirected.
// A valid url_to must be parsed successfully by the url crate.
impl<'v> FromFormValue<'v> for InputUrl {

    type Error = &'v RawStr;
    fn from_form_value(form_value: &'v RawStr) -> Result<InputUrl, &'v RawStr> {
        match Url::parse(&form_value.url_decode_lossy()) {
            Ok(r) => Ok(InputUrl(r.into_string())),
            Err(_) => Err(form_value),
        }
    }
}

// captcha Form value
// captcha is the field filled when the user has to resolve the captcha.
// A valid captcha must be between 4 and 8 characters long.
// Then, the captcha value must be checked.
impl<'v> FromFormValue<'v> for InputCaptcha {

    type Error = &'v RawStr;
    fn from_form_value(form_value: &'v RawStr) -> Result<InputCaptcha, &'v RawStr> {
        match form_value.url_decode_lossy().len() >= 4
        && form_value.url_decode_lossy().len() <= 8 {
            true => Ok(InputCaptcha(form_value.url_decode_lossy())),
            false => Err(form_value),
        }
    }
}

