# providore-client

Command line client for fetching certificates and configurations for *nix machines

**Note:** This is not quite ready for production yet

# Building

## Docker

```
docker buildx create --use desktop-linux
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v6,linux/arm/v7 -t madpilot/providore-client --push .
```
