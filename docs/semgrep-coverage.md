# Semgrep `p/python` coverage

Every rule in Semgrep's `p/python` ruleset as served by the registry on
2026-11-16 (151 rules), classified as **built-in** (a fenceline check
covers the shape), **rule** (expressible in the declarative format of
`docs/rules.md`, with the sketch) or **not expressible** (with why). This
is what lets the README say "replacement" with a straight face, and it is
the list of what to build next.

Reading the "How" column: a built-in named with "at MEDIUM" covers the
sink but not Semgrep's source (a Lambda `event`, `os.environ`), so it
reports the call at MEDIUM confidence rather than HIGH. A rule sketch
marked "wider" reports a superset of what the Semgrep rule reports,
because the format has no `pattern-inside`, `pattern-not` or metavariable
test to narrow it.

**151 rules: 69 built-in, 52 expressible as a rule, 30 not expressible.** Built-in and rule together cover 121 of 151.

| Semgrep rule | CWE | Status | How |
| --- | --- | --- | --- |
| boto3.security.hardcoded-token | 798 | built-in | `check_hardcoded_tokens` (AWS key shapes), `check_hardcoded_secrets` |
| cryptography.security.insecure-cipher-algorithms.insecure-cipher-algorithm-idea | 327 | rule | `call`, callee `cryptography.hazmat.primitives.ciphers.algorithms.IDEA` |
| cryptography.security.insecure-cipher-mode-ecb | 327 | rule | `call`, callee `cryptography.hazmat.primitives.ciphers.modes.ECB` |
| cryptography.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 | 327 | rule | `call`, callee `cryptography.hazmat.primitives.hashes.SHA1` |
| cryptography.security.insufficient-dsa-key-size | 326 | not expressible | `key_size < 2048` is a metavariable comparison |
| cryptography.security.insufficient-ec-key-size | 326 | rule | `pattern`, regex over the weak curve class names (`SECP192R1`, `SECT163K1`, ...) |
| cryptography.security.insufficient-rsa-key-size | 326 | not expressible | `key_size < 2048` is a metavariable comparison |
| distributed.security.require-encryption | 319 | rule | `keyword`, callee `distributed.security.Security`, `require_encryption` `value = false` |
| django.security.audit.avoid-insecure-deserialization | 502 | built-in | `check_pickle`, `check_yaml_deserialize` (every call, not only request-fed) |
| django.security.injection.open-redirect | 601 | built-in | `check_open_redirect` |
| django.security.injection.reflected-data-httpresponse | 79 | rule | `sink`, callee `django.http.HttpResponse` (wider: any tainted content, not only `.format(request...)`) |
| django.security.injection.reflected-data-httpresponsebadrequest | 79 | rule | `sink`, callee `django.http.HttpResponseBadRequest` (wider) |
| django.security.injection.request-data-fileresponse | 22 | rule | `sink`, callee `django.http.FileResponse` |
| django.security.injection.request-data-write | 93 | rule | `sink`, callee `write` (wider: every `.write()` fed data) |
| django.security.injection.code.user-eval-format-string | 95 | built-in | `check_eval_exec` |
| django.security.injection.code.user-eval | 95 | built-in | `check_eval_exec` |
| django.security.injection.code.user-exec-format-string | 95 | built-in | `check_eval_exec` |
| django.security.injection.code.user-exec | 95 | built-in | `check_eval_exec` |
| django.security.injection.command.command-injection-os-system | 78 | built-in | `check_command_injection` |
| django.security.injection.email.xss-html-email-body | 74 | rule | `sink`, callee `django.core.mail.EmailMessage`, `data = [1]` |
| django.security.injection.email.xss-send-mail-html-message | 74 | rule | `sink`, callee `django.core.mail.send_mail`, `data = ["html_message"]` |
| django.security.injection.path-traversal.path-traversal-open | 22 | built-in | `check_path_traversal` |
| django.security.injection.sql.sql-injection-using-extra-where | 89 | not expressible | the format string sits inside a list in the `where=` keyword; `check_sql_injection` covers `raw`/`RawSQL`/`execute`, not `extra` |
| django.security.injection.sql.sql-injection-using-rawsql | 89 | built-in | `check_sql_injection` |
| django.security.injection.sql.sql-injection-db-cursor-execute | 89 | built-in | `check_sql_injection` |
| django.security.injection.sql.sql-injection-using-raw | 89 | built-in | `check_sql_injection` |
| django.security.injection.ssrf.ssrf-injection-requests | 918 | built-in | `check_ssrf` |
| django.security.injection.ssrf.ssrf-injection-urllib | 918 | built-in | `check_ssrf` |
| django.security.passwords.password-empty-string | 521 | not expressible | a positional literal (`set_password("")`) followed by a second statement |
| django.security.passwords.use-none-for-password-default | 521 | not expressible | a statement sequence (`request.POST.get(x, "")` then `set_password`) |
| flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host | 668 | built-in | `check_bind_all_interfaces` |
| flask.security.audit.app-run-security-config.avoid_using_app_run_directly | 668 | not expressible | `pattern-not-inside` (`if __name__ == "__main__"`) |
| flask.security.audit.debug-enabled | 489 | built-in | `check_debug_mode` |
| flask.security.audit.directly-returned-format-string | 79 | not expressible | the sink is a `return` of a format string inside a route, not a call |
| flask.security.injection.os-system-injection | 78 | built-in | `check_command_injection` |
| flask.security.injection.path-traversal-open | 22 | built-in | `check_path_traversal` |
| flask.security.injection.ssrf-requests | 918 | built-in | `check_ssrf` |
| flask.security.injection.user-eval.eval-injection | 95 | built-in | `check_eval_exec` |
| flask.security.injection.user-exec.exec-injection | 95 | built-in | `check_eval_exec` |
| jwt.security.jwt-hardcode.jwt-python-hardcoded-secret | 522 | not expressible | a positional literal (`jwt.encode(x, "...")`) |
| jwt.security.jwt-none-alg | 327 | rule | `keyword`, callee `jwt.encode`, `algorithm` `value = "none"` |
| jwt.security.unverified-jwt-decode | 287 | not expressible | the value is a dict literal (`options={"verify_signature": False}`) |
| lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 | 327 | built-in | `check_weak_hash` |
| lang.security.insecure-hash-function | 327 | built-in | `check_weak_hash` (`hashlib.new("md5")`) |
| lang.security.unverified-ssl-context | 295 | built-in | `check_tls_verify` |
| lang.security.audit.ssl-wrap-socket-is-deprecated | 326 | rule | `call`, callee `ssl.wrap_socket` |
| lang.security.audit.subprocess-shell-true | 78 | built-in | `check_command_injection` |
| lang.security.audit.weak-ssl-version | 326 | built-in | `check_weak_tls_version` |
| lang.security.audit.insecure-transport.requests.request-session-http-in-with-context | 319 | not expressible | taint of an `http://` string literal into a session; `pattern` can see only a literal written at the call |
| lang.security.audit.insecure-transport.requests.request-session-with-http | 319 | not expressible | as above |
| lang.security.audit.insecure-transport.requests.request-with-http | 319 | rule | `pattern`, regex `requests\.\w+\(\s*["']http://` (direct literal only; a variable holding the URL is not followed) |
| lang.security.audit.logging.logger-credential-leak | 532 | built-in | `check_log_secrets` |
| lang.security.audit.network.bind.avoid-bind-to-all-interfaces | 200 | built-in | `check_bind_all_interfaces` |
| lang.security.audit.network.disabled-cert-validation | 295 | built-in | `check_tls_verify` (`CERT_NONE` as a value) |
| lang.security.audit.network.http-not-https-connection | 319 | rule | `call`, callee `urllib3.HTTPConnectionPool` |
| lang.security.deserialization.avoid-pyyaml-load | 502 | built-in | `check_yaml_deserialize` |
| lang.security.deserialization.avoid-unsafe-ruamel | 502 | rule | `keyword`, callee `ruamel.yaml.YAML`, `typ` `value = "unsafe"` |
| lang.security.deserialization.pickle.avoid-shelve | 502 | built-in | `check_pickle` (`shelve.open`) |
| pycryptodome.security.insecure-cipher-algorithm-xor | 327 | rule | `call`, callee `Cryptodome.Cipher.XOR.new`, `Crypto.Cipher.XOR.new` |
| pycryptodome.security.insecure-hash-algorithm-sha1 | 327 | rule | `call`, callee `Crypto.Hash.SHA.new`, `Cryptodome.Hash.SHA.new` |
| pycryptodome.security.insufficient-dsa-key-size | 326 | not expressible | `bits < 2048` is a metavariable comparison |
| pycryptodome.security.insufficient-rsa-key-size | 326 | not expressible | `bits < 2048` is a metavariable comparison |
| sqlalchemy.security.sqlalchemy-sql-injection | 89 | not expressible | `session.query(...).filter("...".format(param))` needs the format call inside a chained method under a `def` with that parameter; `check_sql_injection` covers `text()`/`execute`, not `filter` |
| pymongo.security.mongodb.mongo-client-bad-auth | 477 | rule | `keyword`, callee `pymongo.MongoClient`, `authMechanism` `value = "MONGODB-CR"` |
| lang.security.audit.insecure-file-permissions | 276 | not expressible | an octal mode compared numerically |
| django.security.injection.raw-html-format | 79 | built-in | `check_unsafe_markup` |
| flask.security.injection.raw-html-concat | 79 | built-in | `check_unsafe_markup` |
| flask.security.injection.tainted-url-host | 918 | built-in | `check_ssrf` |
| flask.security.injection.tainted-sql-string | 704 | built-in | `check_sql_injection` |
| lang.security.audit.md5-used-as-password | 327 | built-in | `check_weak_hash` (credential context is HIGH) |
| sqlalchemy.security.audit.avoid-sqlalchemy-text | 89 | built-in | `check_sql_injection` (`text()`) |
| aws-lambda.security.dangerous-asyncio-create-exec | 78 | built-in | `check_command_injection`, at MEDIUM (a Lambda `event` is not a modelled source) |
| aws-lambda.security.dangerous-asyncio-exec | 78 | built-in | `check_command_injection`, at MEDIUM |
| aws-lambda.security.dangerous-asyncio-shell | 78 | built-in | `check_command_injection`, at MEDIUM |
| aws-lambda.security.dangerous-spawn-process | 78 | built-in | `check_command_injection`, at MEDIUM |
| aws-lambda.security.dangerous-subprocess-use | 78 | built-in | `check_command_injection`, at MEDIUM |
| aws-lambda.security.dangerous-system-call | 78 | built-in | `check_command_injection`, at MEDIUM |
| aws-lambda.security.mysql-sqli | 89 | built-in | `check_sql_injection`, at MEDIUM |
| aws-lambda.security.psycopg-sqli | 89 | built-in | `check_sql_injection`, at MEDIUM |
| aws-lambda.security.pymssql-sqli | 89 | built-in | `check_sql_injection`, at MEDIUM |
| aws-lambda.security.pymysql-sqli | 89 | built-in | `check_sql_injection`, at MEDIUM |
| aws-lambda.security.sqlalchemy-sqli | 89 | built-in | `check_sql_injection`, at MEDIUM |
| aws-lambda.security.tainted-code-exec | 95 | built-in | `check_eval_exec`, at MEDIUM |
| aws-lambda.security.tainted-html-response | 79 | not expressible | the sink is the returned response dict's `body`, not a call |
| aws-lambda.security.tainted-sql-string | 89 | built-in | `check_sql_injection`, at MEDIUM |
| django.security.nan-injection | 704 | rule | `sink`, callee `float`, `data = "first"` (wider: any tainted `float()`) |
| flask.security.injection.nan-injection | 704 | rule | `sink`, callee `float`, `data = "first"` (wider) |
| aws-lambda.security.tainted-html-string | 79 | not expressible | string building (`"<html>" + event[...]`), not a call |
| jinja2.security.audit.autoescape-disabled-false.incorrect-autoescape-disabled | 116 | rule | `keyword`, callee `jinja2.Environment`, `autoescape` `value = false` |
| jinja2.security.audit.missing-autoescape-disabled | 116 | rule | `keyword`, callee `jinja2.Environment`, `autoescape` `required = true` |
| aws-lambda.security.dynamodb-filter-injection | 943 | rule | `sink`, callee `scan`, `query`, `data = ["FilterExpression", "KeyConditionExpression"]` (wider: any `.scan()`/`.query()`) |
| pyramid.audit.authtkt-cookie-httponly-unsafe-default | 1004 | rule | `keyword`, callee `pyramid.authentication.AuthTktCookieHelper`, `pyramid.authentication.AuthTktAuthenticationPolicy`, `httponly` `required = true` |
| pyramid.audit.authtkt-cookie-httponly-unsafe-value | 1004 | rule | `keyword`, same callees, `httponly` `value = false` |
| pyramid.audit.authtkt-cookie-samesite | 1275 | not expressible | the test is a regex over the value (`samesite` not `Strict`/`Lax`); `unless` tests one literal |
| pyramid.audit.authtkt-cookie-secure-unsafe-default | 614 | rule | `keyword`, same callees, `secure` `required = true` |
| pyramid.audit.authtkt-cookie-secure-unsafe-value | 614 | rule | `keyword`, same callees, `secure` `value = false` |
| pyramid.audit.csrf-origin-check-disabled-globally | 352 | not expressible | an assignment compared to a constant inside a config block |
| pyramid.audit.csrf-origin-check-disabled | 352 | not expressible | as above |
| pyramid.audit.set-cookie-httponly-unsafe-default | 1004 | rule | `keyword`, callee `set_cookie`, `httponly` `required = true` (wider: every `set_cookie`, not only Pyramid's) |
| pyramid.audit.set-cookie-httponly-unsafe-value | 1004 | rule | `keyword`, callee `set_cookie`, `httponly` `value = false` (wider) |
| pyramid.audit.set-cookie-samesite-unsafe-default | 1275 | rule | `keyword`, callee `set_cookie`, `samesite` `required = true` (wider) |
| pyramid.audit.set-cookie-samesite-unsafe-value | 1275 | not expressible | a regex over the value |
| pyramid.audit.set-cookie-secure-unsafe-default | 614 | rule | `keyword`, callee `set_cookie`, `secure` `required = true` (wider) |
| pyramid.audit.set-cookie-secure-unsafe-value | 614 | rule | `keyword`, callee `set_cookie`, `secure` `value = false` (wider) |
| pyramid.security.csrf-check-disabled-globally | 352 | not expressible | an assignment compared to a constant |
| pyramid.security.direct-use-of-response | 79 | rule | `sink`, callee `pyramid.response.Response`, `data = "first"` |
| pyramid.security.sqlalchemy-sql-injection | 89 | built-in | `check_sql_injection` |
| aws-lambda.security.tainted-pickle-deserialization | 502 | built-in | `check_pickle` |
| lang.security.audit.dangerous-asyncio-exec-tainted-env-args | 78 | built-in | `check_command_injection`, at MEDIUM (`os.environ` is INTERNAL) |
| lang.security.audit.dangerous-asyncio-shell-tainted-env-args | 78 | built-in | `check_command_injection`, at MEDIUM |
| lang.security.audit.dangerous-code-run-tainted-env-args | 95 | rule | `sink`, callee `code.InteractiveConsole.runcode`, `runcode`, `runsource`, `data = "first"` (at MEDIUM) |
| lang.security.audit.dangerous-os-exec-tainted-env-args | 78 | built-in | `check_command_injection`, at MEDIUM |
| lang.security.audit.dangerous-spawn-process-tainted-env-args | 78 | built-in | `check_command_injection`, at MEDIUM |
| lang.security.audit.dangerous-subinterpreters-run-string-tainted-env-args | 95 | rule | `sink`, callee `_xxsubinterpreters.run_string`, `data = [1]` (at MEDIUM) |
| lang.security.audit.dangerous-subprocess-use-tainted-env-args | 78 | built-in | `check_command_injection`, at MEDIUM |
| lang.security.audit.dangerous-system-call-tainted-env-args | 78 | built-in | `check_command_injection`, at MEDIUM |
| lang.security.audit.dangerous-testcapi-run-in-subinterp-tainted-env-args | 95 | rule | `sink`, callee `_testcapi.run_in_subinterp`, `data = "first"` (at MEDIUM) |
| lang.security.dangerous-code-run | 95 | rule | `sink`, callee `code.InteractiveConsole.runcode`, `runcode`, `runsource` |
| lang.security.dangerous-os-exec | 78 | built-in | `check_command_injection` |
| lang.security.dangerous-spawn-process | 78 | built-in | `check_command_injection` |
| lang.security.dangerous-subinterpreters-run-string | 95 | rule | `sink`, callee `_xxsubinterpreters.run_string`, `data = [1]` |
| lang.security.dangerous-subprocess-use | 78 | built-in | `check_command_injection` |
| lang.security.dangerous-system-call | 78 | built-in | `check_command_injection` |
| lang.security.dangerous-testcapi-run-in-subinterp | 95 | rule | `sink`, callee `_testcapi.run_in_subinterp`, `data = "first"` |
| django.security.injection.command.subprocess-injection | 78 | built-in | `check_command_injection` |
| django.security.injection.csv-writer-injection | 1236 | rule | `sink`, callee `writerow`, `writerows` (wider: every CSV writer) |
| flask.security.injection.csv-writer-injection | 1236 | rule | `sink`, callee `writerow`, `writerows` (wider) |
| flask.security.injection.subprocess-injection | 78 | built-in | `check_command_injection` |
| cryptography.security.mode-without-authentication | 327 | not expressible | `pattern-not-inside` (no HMAC in the same scope) |
| pycryptodome.security.mode-without-authentication | 327 | not expressible | `pattern-not-inside` |
| cryptography.security.insecure-cipher-algorithms-arc4 | 327 | built-in | `check_weak_crypto` (`ARC4`) |
| cryptography.security.insecure-cipher-algorithms-blowfish | 327 | rule | `call`, callee `cryptography.hazmat.primitives.ciphers.algorithms.Blowfish` |
| cryptography.security.insecure-hash-algorithms-md5 | 327 | rule | `call`, callee `cryptography.hazmat.primitives.hashes.MD5` |
| lang.security.insecure-hash-algorithms-md5 | 327 | built-in | `check_weak_hash` |
| pycryptodome.security.insecure-cipher-algorithm-blowfish | 327 | rule | `call`, callee `Cryptodome.Cipher.Blowfish.new`, `Crypto.Cipher.Blowfish.new` |
| pycryptodome.security.insecure-cipher-algorithm-des | 327 | built-in | `check_weak_crypto` (`Crypto.Cipher.DES`); add a `call` rule for `Cryptodome.Cipher.DES.new` |
| pycryptodome.security.insecure-cipher-algorithm-rc2 | 327 | rule | `call`, callee `Cryptodome.Cipher.ARC2.new`, `Crypto.Cipher.ARC2.new` |
| pycryptodome.security.insecure-cipher-algorithm-rc4 | 327 | built-in | `check_weak_crypto` (`ARC4`) |
| pycryptodome.security.insecure-hash-algorithm-md2 | 327 | rule | `call`, callee `Crypto.Hash.MD2.new`, `Cryptodome.Hash.MD2.new` |
| pycryptodome.security.insecure-hash-algorithm-md4 | 327 | rule | `call`, callee `Crypto.Hash.MD4.new`, `Cryptodome.Hash.MD4.new` |
| pycryptodome.security.insecure-hash-algorithm-md5 | 327 | rule | `call`, callee `Crypto.Hash.MD5.new`, `Cryptodome.Hash.MD5.new` |
| cryptography.security.empty-aes-key | 327 | not expressible | a positional literal (`AES.new("")`) |
| django.security.hashids-with-django-secret | 327 | not expressible | the keyword value is a dotted name (`settings.SECRET_KEY`) |
| flask.security.hashids-with-flask-secret | 327 | not expressible | the keyword value is a subscript (`config['SECRET_KEY']`) |
| lang.security.use-defused-xml-parse | 611 | built-in | `check_xxe` |
| django.security.django-using-request-post-after-is-valid | 20 | not expressible | a statement sequence (`is_valid()` then `request.POST[...]`) |
| fastapi.security.wildcard-cors | 942 | not expressible | the value is a list containing `"*"` |
| twilio.security.twiml-injection | 91 | not expressible | the sink is every TwiML verb method on a response object |
| lang.security.insecure-uuid-version | 330 | rule | `call`, callee `uuid.uuid1` |
| lang.security.audit.sha224-hash | 327 | rule | `call`, callee `hashlib.sha224` |
| flask.security.audit.flask-url-for-external-true | 673 | rule | `keyword`, callee `flask.url_for`, `_external` `value = true` (wider: Semgrep excludes calls under an `https` scheme check) |

## Where the format stops

The "not expressible" rows fall into five shapes, in order of frequency:
a comparison or regex over a value (key sizes, `samesite`, file modes), a
positional literal (`jwt.encode(x, "...")`, `AES.new("")`,
`set_password("")`), a sequence of statements, a context condition
(`pattern-inside` / `pattern-not-inside`), and a sink that is not a call (a
`return`, a response dict, string concatenation). Each is a Python plugin
today; a positional-literal test and a value regex are the two cheapest
additions to the format if they are wanted.
