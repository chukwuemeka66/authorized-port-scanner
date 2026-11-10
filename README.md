# Authorized Port Scanner

## JPEG validation

`ValidateJPEG` checks that in-memory data starts with the JPEG marker `FF D8 FF`
and ends with `FF D9`. The commonly cited 15 MB size is a guideline, not an
enforced maximum.

## Offline file carving

The carver scans a user-selected regular image file in read-only mode and writes
recovered JPEG, PNG, PDF, ZIP, and ELF files to a separate output directory. It
does not open raw devices or modify the source image. JPEG, PNG, PDF, and ZIP
carves end at their listed footer markers; the 15 MB JPEG figure is only a
guideline and those types have no enforced size cap. ZIP-based DOCX and XLSX
files are recovered with a `.zip` extension because the local-file signature
does not identify their specific document type.

ELF files have no footer, so each ELF carve extends to EOF or the configured
limit, whichever comes first. The default limit is 15 MiB per ELF and can be
changed with `-carve-elf-max-bytes`. Recovery events include the start offset,
file size, and SHA-256 hash; file contents are not sent to Splunk.

Set `SPLUNK_HEC_URL` and `SPLUNK_HEC_TOKEN`, then run:

```text
go run main.go nodezero.go splunk_ship.go xbow.go tracking.go carver.go -carve-image disk.img -carve-output recovered
```

The output directory must differ from the image's directory. Existing carved
file names are never overwritten. Recovered files are written before their
metadata is shipped; if Splunk shipping fails, the files remain in the output
directory and the command reports the error.

## NodeZero configuration

Set these environment variables to configure the Horizon3 NodeZero client:

| Variable | Description |
| --- | --- |
| `H3_AUTH_URL` | Authentication endpoint |
| `H3_GRAPHQL_URL` | GraphQL endpoint used to retrieve attack paths |
| `H3_API_KEY` | API key generated in the Horizon3/XBOW portal |

Example values:

```text
H3_AUTH_URL=https://api.gateway.horizon3.ai/v1/auth
H3_GRAPHQL_URL=https://api.gateway.horizon3.ai/v1/graphql
H3_API_KEY=your_nodezero_api_key
```

Set `H3_API_KEY` to your own key; do not commit real credentials to the repository.
The application accepts custom endpoint URLs through `H3_AUTH_URL` and
`H3_GRAPHQL_URL`. Confirm the correct endpoint domain for your account before
running it.

NodeZero API endpoints must use HTTPS. HTTP is accepted only for local tests
using `localhost` or `127.0.0.1`. Endpoint URLs must not contain embedded
credentials, query strings, or fragments.

## Splunk HEC configuration

Set these variables to ship NodeZero attack-path metadata to Splunk:

| Variable | Description |
| --- | --- |
| `SPLUNK_HEC_URL` | Splunk HEC URL, such as `https://your-splunk-instance:8088/services/collector` |
| `SPLUNK_HEC_TOKEN` | Token created in Splunk Web under **Settings > Data Inputs > HTTP Event Collector** |

Keep the HEC token private and do not commit it to the repository.

## Local tracking endpoint

Run `go run main.go nodezero.go splunk_ship.go xbow.go tracking.go -tracking-server`
to start an opt-in tracking endpoint at `http://127.0.0.1:8080/track`. It logs
the direct peer IP address and ignores `X-Forwarded-For`; the listener is bound
to loopback and is not exposed to other machines by default.
