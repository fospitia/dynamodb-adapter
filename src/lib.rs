mod adapter;
mod errors;

pub use casbin;

pub use crate::adapter::DynamoDBAdapter;
pub use crate::errors::ParsePolicyFailed;

#[cfg(test)]
mod tests {
    use aws_sdk_dynamodb::{
        model::{AttributeDefinition, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType},
        Client, Endpoint,
    };
    use casbin::{
        function_map::{glob_match, key_match},
        Adapter,
    };
    use http::Uri;

    use crate::adapter::DynamoDBAdapter;

    const TABLE_NAME: &str = "Casbin_Policies";

    fn to_owned(v: Vec<&str>) -> Vec<String> {
        v.into_iter().map(|x| x.to_owned()).collect()
    }

    async fn init_table(client: &Client) {
        client
            .delete_table()
            .table_name(TABLE_NAME.to_string())
            .send()
            .await
            .ok();

        let ad = AttributeDefinition::builder()
            .attribute_name("id".to_string())
            .attribute_type(ScalarAttributeType::S)
            .build();

        let ks = KeySchemaElement::builder()
            .attribute_name("id".to_string())
            .key_type(KeyType::Hash)
            .build();

        client
            .create_table()
            .table_name(TABLE_NAME.to_string())
            .attribute_definitions(ad)
            .key_schema(ks)
            .billing_mode(BillingMode::PayPerRequest)
            .send()
            .await
            .ok();
    }

    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_adapter() -> std::result::Result<(), casbin::Error> {
        use casbin::prelude::*;

        let config = aws_config::load_from_env().await;
        let dynamodb_local_config = aws_sdk_dynamodb::config::Builder::from(&config)
            .endpoint_resolver(Endpoint::immutable(Uri::from_static(
                "http://localhost:8000",
            )))
            .build();

        let client = Client::from_conf(dynamodb_local_config);

        init_table(&client).await;

        let file_adapter = FileAdapter::new("examples/rbac_policy.csv");
        let m = DefaultModel::from_file("examples/rbac_model.conf").await?;
        let mut e = Enforcer::new(m, file_adapter).await.unwrap();

        let mut adapter = DynamoDBAdapter::new(&client, TABLE_NAME)?;

        assert!(adapter.save_policy(e.get_mut_model()).await.is_ok());

        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["alice", "data1", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["bob", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());

        assert!(adapter
            .add_policy("", "p", to_owned(vec!["alice", "data1", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "p", to_owned(vec!["bob", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "p", to_owned(vec!["data2_admin", "data2", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "p", to_owned(vec!["data2_admin", "data2", "write"]))
            .await
            .is_ok());

        assert!(adapter
            .remove_policies(
                "",
                "p",
                vec![
                    to_owned(vec!["alice", "data1", "read"]),
                    to_owned(vec!["bob", "data2", "write"]),
                    to_owned(vec!["data2_admin", "data2", "read"]),
                    to_owned(vec!["data2_admin", "data2", "write"]),
                ]
            )
            .await
            .is_ok());

        assert!(adapter
            .add_policies(
                "",
                "p",
                vec![
                    to_owned(vec!["alice", "data1", "read"]),
                    to_owned(vec!["bob", "data2", "write"]),
                    to_owned(vec!["data2_admin", "data2", "read"]),
                    to_owned(vec!["data2_admin", "data2", "write"]),
                ]
            )
            .await
            .is_ok());

        assert!(adapter
            .add_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());

        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["alice", "data1", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["bob", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());

        assert!(!adapter
            .remove_policy(
                "",
                "g",
                to_owned(vec!["alice", "data2_admin", "not_exists"])
            )
            .await
            .unwrap());

        assert!(adapter
            .add_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());
        // In DynamoDB next call no throw error
        assert!(adapter
            .add_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());

        assert!(!adapter
            .remove_filtered_policy(
                "",
                "g",
                0,
                to_owned(vec!["alice", "data2_admin", "not_exists"]),
            )
            .await
            .unwrap());

        assert!(adapter
            .remove_filtered_policy("", "g", 0, to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());

        assert!(adapter
            .add_policy(
                "",
                "g",
                to_owned(vec!["alice", "data2_admin", "domain1", "domain2"]),
            )
            .await
            .is_ok());
        assert!(adapter
            .remove_filtered_policy(
                "",
                "g",
                1,
                to_owned(vec!["data2_admin", "domain1", "domain2"]),
            )
            .await
            .is_ok());

        // shadow the previous enforcer
        let mut e = Enforcer::new(
            "examples/rbac_with_domains_model.conf",
            "examples/rbac_with_domains_policy.csv",
        )
        .await
        .unwrap();

        assert!(adapter.save_policy(e.get_mut_model()).await.is_ok());
        e.set_adapter(adapter).await.unwrap();

        let filter = Filter {
            p: vec!["", "domain1"],
            g: vec!["", "", "domain1"],
        };

        e.load_filtered_policy(filter).await.unwrap();
        assert!(e.enforce(("alice", "domain1", "data1", "read")).unwrap());
        assert!(e.enforce(("alice", "domain1", "data1", "write")).unwrap());
        assert!(!e.enforce(("alice", "domain1", "data2", "read")).unwrap());
        assert!(!e.enforce(("alice", "domain1", "data2", "write")).unwrap());
        assert!(!e.enforce(("bob", "domain2", "data2", "read")).unwrap());
        assert!(!e.enforce(("bob", "domain2", "data2", "write")).unwrap());

        Ok(())
    }

    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_casbin_adapter() -> std::result::Result<(), casbin::Error> {
        use casbin::prelude::*;

        let config = aws_config::load_from_env().await;
        let dynamodb_local_config = aws_sdk_dynamodb::config::Builder::from(&config)
            .endpoint_resolver(Endpoint::immutable(Uri::from_static(
                "http://localhost:8000",
            )))
            .build();

        let client = Client::from_conf(dynamodb_local_config);

        init_table(&client).await;

        let m = DefaultModel::from_file("examples/rbac_model.conf").await?;
        let adapter = DynamoDBAdapter::new(&client, TABLE_NAME)?;
        let mut e = Enforcer::new(m, adapter).await?;

        let rm = e.get_role_manager();
        rm.write().matching_fn(Some(key_match), Some(glob_match));

        e.add_policy(to_owned(vec!["alice", "data1", "read"]))
            .await?;

        assert!(e.enforce(("alice", "data1", "read")).is_ok());

        e.remove_policy(to_owned(vec!["alice", "data1", "read"]))
            .await?;

        e.save_policy().await?;

        Ok(())
    }

}
