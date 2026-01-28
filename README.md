# tinymount

Cloud storage that mounts like a drive.

```bash
tinymount create datasets --size 500GB
tinymount mount datasets ~/data
# That's it. Use ~/data like any directory.
```

## Install

```bash
curl -sSL https://tinymount.com/install.sh | sh
```

Or download from [releases](https://github.com/tinyworks-io/tinymount/releases).

### Requirements

- **Linux** or **macOS** (Apple Silicon or Intel)
- FUSE: `apt install fuse` or `brew install macfuse`
- JuiceFS: installed automatically or via `brew install juicefs`

## Quick Start

```bash
# Create account
tinymount register

# Create an encrypted volume
tinymount create my-data
# Enter a password when prompted

# Mount it
tinymount mount my-data ~/cloud
# Enter same password

# Use it
cp -r ~/projects ~/cloud/
ls ~/cloud/

# Unmount when done
tinymount unmount ~/cloud
```

## Commands

```
tinymount register          Create account
tinymount login             Log in
tinymount logout            Log out
tinymount whoami            Show current user

tinymount create <name>     Create volume (encrypted by default)
tinymount list              List volumes
tinymount info <name>       Show volume details
tinymount destroy <name>    Delete volume

tinymount mount <name> <path>   Mount volume
tinymount unmount <path>        Unmount
tinymount status                Show active mounts

tinymount regions               List available regions
tinymount regions --test-latency   Find fastest region

tinymount usage             Show billing usage
```

## Regions

Choose a region close to you for best performance:

```bash
tinymount regions --test-latency
```

| Code | Location |
|------|----------|
| wnam | Los Angeles |
| enam | Ashburn, VA |
| weur | Amsterdam |
| eeur | Helsinki |
| apac | Singapore |

```bash
tinymount create my-data --region enam
```

## Encryption

All volumes are encrypted by default.

- AES-256-GCM encryption via JuiceFS
- Password never leaves your machine
- Same password works on any device
- If you forget your password, data is unrecoverable

Use `--no-encryption` if you don't need encryption (not recommended).

## Pricing

| Tier | Price | Details |
|------|-------|---------|
| Free | $0 | 5 GB included |
| Pay as you go | $0.03/GB/mo | Unlimited storage |
| Pro | $5/mo + storage | Up to 5 devices |

Zero egress fees on all plans.

## Development

```bash
# Build
go build -o tinymount .

# Use local API
./tinymount --dev login
```

## License

MIT
