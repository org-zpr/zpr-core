# ZPL Compiler

Can compile simple (new) ZPL into binary policies that the prototype visa service
can process.

## Example usage

```bash
./zpc -k path/to/rsa-key.pem path/to/policy.zpl
```

- That RSA key in the invocation is used to sign the binary policy so
  must match the one that the visa service is configured with.
- By default the _configuration_ for the ZPL policy will be found in a
  file with the same name as the ZPL file but with the `zplc` extension.
  If you want to loca configuration from somewhre else, use
  `-c path/to/config.zplc` argument.
- Help is available via `zpc -h`



## Tentative Grammer

Note that this is just enough grammer to meet current compiler needs.



```

ignored-tokens  : 'a', 'an'

statement       : ( allow-statement | define-statement ) + <eos>

eos             : EOF | '\n' | '.'

allow-statement : 'allow' + <device-clause> + 'with' + <user-clause> + 'to access' + <service-clause>

define-statement: 'define' + class-name-decl + 'as a' + class-name + 'with' + attr-name-list [ + 'and with' + attr-name-list...]

class-name-decl : class-name | class-name + 'AKA' + class-name-syn

where T is one of ( device, user, service ) {

    T-clause        : attr-list + T-class + [ 'without' + attr-list ]

    T-class         : 'T' | PLURAL(T) | class-name | class-name-syn
}

attr-list       : attribute | attribute + and + attribute...

attr-name-list  : attr-name-expr  [ + and + attr-name-expr ]... [ + 'from' source-name]

atrr-name-expr  : attr-name
                  | tuple
                  | 'optional' + ( attr-name | ( 'tags' | 'tag' ) + attr-name-list )
                  | 'multiple' + attr-name
                  | ( 'tag' | 'tags' ) + attr-name-list

attribute       : tuple | attr-name

tuple           : attr-name + ':' + attr-value

attr-name       : string | name

attr-value      : string | integer

name            : string | [ <name> + '.' + <name> ]

class-name      : string
class-name-syn  : string
source-name     : string

and             : ',' | 'and' | ', and'

string          : sequence of [A-Za-z0-9\-_] | quote + sequence of characters + quote

quote           : forward or backward single quotation (does not need to match)
                  two successive single quotes "escapes" the single quote and so is included in string

```
