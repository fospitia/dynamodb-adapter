# dynamodb-adapter

AWS DynamoDB Adapter is the [DynamoDB](https://github.com/fospitia/dynamodb) adapter for [Casbin-rs](https://github.com/casbin/casbin-rs). With this library, Casbin can load policy from DynamoDB database or save policy to it.

Based on [Diesel](https://github.com/casbin-rs/diesel-adapter) adapter.

## Install

Add it to `Cargo.toml`

```
aws-config = "0.48.0"
aws-sdk-dynamodb = "0.18.0"
dynamodb-adapter = "0.1.0"
tokio = { version = "1.21.1",  features = ["macros", "rt-multi-thread"] }
```

## Example

```rust
use dynamodb_adapter::casbin::prelude::*;
use dynamodb_adapter::DynamoDBAdapter;

#[tokio::main]
async fn main() -> Result<()> {
    let config = aws_config::load_from_env().await;
    let client = aws_sdk_dynamodb::Client::new(&config);

    let m = DefaultModel::from_file("examples/rbac_model.conf").await?;
    let a = DynamoDBAdapter::new(&client, "Casbin_Policies")?;
    let _e = Enforcer::new(m, a).await?;
    Ok(())
}
```

## Test with DynamoBD Local

```shell
docker pull amazon/dynamodb-local
```

```shell
docker run --rm -p 8000:8000 amazon/dynamodb-local
```

```shell
aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name Casbin_Policies \
    --attribute-definitions \
        AttributeName=id,AttributeType=S \
    --key-schema \
        AttributeName=id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST
```

```shell
aws dynamodb scan \
    --endpoint-url http://localhost:8000 \
    --table-name Casbin_Policies
```
