# rs-short

Link shortener in Rust.

Developed to be as minimalist and lightweight as possible.

Powered by the [Rocket](https://rocket.rs) framework using (server-side) Handlebars templates.

- Less than 1000 lines of code, including 20% of comments
- Consumes between 5MB and 20MB of RAM
- No JS
- No CSS framework ; CSS is handmade and all rules are prefixed to avoid rule conflicts
- No tracking features at all
- No `unsafe` block

Features:
- Includes a captcha as a minimal protection against spamming
- Easily customizable assets
- Only needs a SQLite database to work
- Localization (available in French and English)
- Counting clicks
- Allows shortcut deletion

**Official instance:** https://s.42l.fr/

## Running an instance

First, you must install Cargo and the latest stable version of Rust by following the instructions on [this website](https://rustup.rs/). Alternatively, you can use the [liuchong/rustup](https://hub.docker.com/r/liuchong/rustup) Docker image.

- Clone the project:

```bash
git clone https://git.42l.fr/42l/rs-short.git
```

- Edit what you need. You might want to change the following files:
    - `assets/hoster-logo.png`: replace with the logo of your organization
    - `assets/logo.svg`: the software logo
    - `assets/background.jpg`: the default background

- Copy `config.toml.sample` to `config.toml` and edit its values to suit your needs.

- Create a file named `Rocket.toml` at the project root, containing the following:

```toml
[global]
address = "<ADDRESS>"
template_dir = "templates"
secret_key = "<SECRET KEY>"

[global.databases.sqlite_database]
url = "db/db.sqlite"
```

- Replace `<ADDRESS>` by the address to listen on
- Replace `<SECRET KEY>` by the result of the command `openssl rand -base64 32`
- Eventually change the database storage path.
You can specify more parameters following the [Rocket documentation](https://api.rocket.rs/v0.4/rocket/config/index.html).

- Edit blacklists at your convenience.
    - `banned_url_from.list`: Any client that submits a *link name* **fully matching** one of the elements in this list will get a 403 Forbidden HTTP status code.
    - `banned_url_to.list`: Any client that submits an *URL* **containing** one of the elements in this list will get a 403 Forbidden HTTP status code.

You can configure a `fail2ban` instance to watch your favourite reverse-proxy logs to see which IPs are getting a 403 and ban accordingly for the duration of your choice.

- `cargo run --release`

## Contributing

The initial version of the software has been developed in one week ; there's still a lot to do.

Here are many ways to contribute:
- Translate!
    - Add your entries in the `lang.json` file.
    - Once you're done, edit `templates.rs` and add your language in the ValidLanguages structure.
- Improve the software modularity
    - Add a configuration file
    - Configure instance and hoster's hostname from the configuration file
    - Toggle captcha
- Add postgresql compatibility
- Add different CSS themes (a dark theme would be a great start!)
- Develop a more resilient protection to spambots
    - Improve hostname blacklisting ?
    - Blacklist shortcut names ?
    - Integrate a ban / ratelimiting system ? (the current system relies entirely on a separate fail2ban instance)
- Clean up the code
    - Restructure the rocket routes in `main.rs` to something more readable
    - Make a better usage of template contexts
    - Improve the forms if you're knowledgeable in Rocket forms
    - Separate the code into more files if necessary

This software is mainly developed and maintained by [Neil](https://shelter.moe/@Neil) for the [Association 42l](https://42l.fr). 

If you like the work done on this project, please consider to [donate or join](https://42l.fr/Support-us) the association. Thank you!


## Graphical credits

- Link Shortener logo by [Brume](https://shelter.moe/@Brume).
- Link Shortener logo font is Hylia Serif by [Artsy Omni](http://artsyomni.com/hyliaserif).
- Default background by [Love-Kay on deviantart](https://www.deviantart.com/love-kay/art/Abstract-Colorful-Watercolor-Texture-438376516).
- Website font by [Ubuntu](https://design.ubuntu.com/font/)
