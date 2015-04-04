# Authentication backend for PHPFox

## Configuration

Change your `prosody.cfg.lua` file to use `phpfox` as authentication backend:

```
authentication = "phpfox"

```

Configure the connection parameters to the PHPFox database:

```
phpfox = {
    driver = "MySQL",
    database = "my_database",
    username = "root",
    password = "root",
    host = "localhost",
    prefix="mysite",
    avatar_path="/avatar/path",
    avatar_prefix="_200_square"
}
```

