```shell
$ credential --help

  Usage: cmd [options] [command]


  Commands:

    hash [options] [password]  Hash password
    verify [hash] <password>   Verify password

  Options:

    -h, --help  output usage information
```

```shell
$ credential hash --help

  Usage: hash [options] [password]

  Hash password

  Options:

    -h, --help                    output usage information
    -w --work <work>              relative work load (0.5 for half the work)
    -k --key-length <key-length>  length of salt
```

The `password` argument for `hash` and the `hash` argument for `verify` both support piping by replacing with a dash (`-`):

```shell
$ echo -n "my password" | credential hash - | credential verify - "my password"
Verified
```

Exit codes `0` and `1` are used to communicate verified or invalid as well.
