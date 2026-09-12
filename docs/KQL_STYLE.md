# KQL style guide

## Conventions

- Put `Surface`, `Purpose`, and `Required data` comments first.
- Expose time windows, thresholds, and lists as `let` statements.
- Filter time and high-selectivity predicates early.
- Normalize only fields needed for comparison; preserve original values in output.
- Use `=~`/`in~` for case-insensitive exact matching, `has`/`has_any` for **whole-term** matching, and
  `contains` for substrings.
- Project analyst-relevant fields and order newest evidence first.
- Add comments where field semantics or tradeoffs are not obvious.

## Performance

Avoid unbounded searches, premature broad `union`, regular expressions when token/string operators suffice, and joins before filtering. Summarize before joining when raw-event detail is not needed. In scheduled rules, keep lookback aligned with frequency and ingestion delay.

## Time fields

Defender advanced hunting uses `Timestamp`; Log Analytics commonly uses `TimeGenerated`; ASIM exposes `EventStartTime`. Preserve the native field in output and add a normalized alias only when a downstream rule requires it.

## Entity output

Where available, return:

- account name and domain or UPN;
- device ID/name;
- source/destination IP and URL/domain;
- image, parent image, command line, and SHA-1/SHA-256;
- event time, count, first seen, and last seen;
- fields that explain why the event matched.

## Sentinel scheduled rules

Entity mappings and custom details are configured outside raw KQL. Keep stable columns in the final projection so deployers can map them. Do not hide threshold values inside nested expressions.

## `has` versus `contains`: the mistake this library shipped in v1

`has` matches whole terms after tokenisation on non-alphanumeric characters. That makes it fast and
correct for words — `Cmd has "lsass"` is right — and quietly **wrong** for anything containing
punctuation. Version 1.0.0 of this repository used constructs like:

```kusto
| where Cmd has_any ("\appdata\", "\users\public\")   // wrong
| where Cmd has_any (" -enc ", " /create ")               // wrong
```

Path fragments, switches with leading spaces, and file extensions are not terms. Tokenisation strips
the delimiters, so the predicate does not mean what it reads as, and matches are unreliable. The v2
rule is mechanical:

| Pattern | Operator | Example |
|---|---|---|
| A word or token | `has` / `has_any` | `Cmd has "minidump"` |
| A path fragment | `contains` | `Cmd contains "\users\public\"` |
| A switch or flag | `contains` | `Cmd contains "-enc"` |
| An extension | `endswith` / `contains` | `FileName endswith ".dmp"` |
| An exact value | `=~` / `in~` | `FileName =~ "rundll32.exe"` |
| A structured pattern | `matches regex` | `Cmd matches regex @"\s-v\d+[kmg]\b"` |

`contains` is slower than `has` on large tables. Pay that cost deliberately where correctness needs
it, and keep the cheap term match where the data is a term.

## Parameter blocks

Every query starts with a `let` block naming its tunable values, and every tunable value appears in
the playbook's tunable-parameter table alongside the ATT&CK mutable element it corresponds to. A
threshold buried inside a `where` clause is a threshold nobody will ever tune.

## Baseline companions

Where a query depends on a threshold, it ends with a commented baseline query that computes the
distribution the threshold should come from. Shipping the threshold without the means to derive it
locally is how public detection content becomes someone else's opinion about your environment.
