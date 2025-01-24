# ZPL Compiler

Work in progress.



## Tentative Grammer

Note that this is just enough grammer to meet current compiler needs.




```


ignored-tokens  : 'a', 'an'

statement       : ( allow-statement | define-statement ) + '\n'

allow-statement : 'allow' + <endpoint-clause> + ( 'with' | 'without' ) + <user-clause> + 'to access' + <service-clause>

define-statement: 'define' + class-name-decl + 'as a' + class-name + 'with' + attr-name-list [ + 'and with' + attr-name-list...]

class-name-decl : class-name | class-name + 'AKA' + class-name-syn

where T is one of ( endpoint, user, service ) {

    T-clause        : T-class + ( 'with' | 'without' ) + attr-list
                      | attr-list + T-class

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

attr-name       : string | ns-name + '.' + name

attr-value      : string | integer

ns-name         : string | ns-name + '.' + string

class-name      : string
class-name-syn  : string

source-name     : string

and             : ',' | 'and' | ', and'

string          : sequence of [A-Za-z0-9\-_] | quote + sequence of characters + quote

quote           : forward or backward single quotation (does not need to match)
                  two successive single quotes "escapes" the single quote and so is included in string

```
