use std::collections::HashMap;

use crate::ParsePolicyFailed;

use async_trait::async_trait;
use aws_sdk_dynamodb::{
    model::{AttributeValue, DeleteRequest, PutRequest, ReturnValue, WriteRequest},
    Client,
};
use casbin::{error::AdapterError, Adapter, Filter, Model, Result};

use tokio_stream::StreamExt;

#[derive(Debug)]
pub struct DynamoDBAdapter {
    client: Client,
    table_name: String,
    is_filtered: bool,
}

impl DynamoDBAdapter {
    pub fn new(client: &Client, table_name: &str) -> Self {
        Self {
            client: client.clone(),
            table_name: table_name.to_string(),
            is_filtered: false,
        }
    }

    fn get_item_id(&self, ptype: &str, rule: &Vec<String>) -> Result<String> {
        let mut line = String::from(ptype);

        for i in 0..6 {
            if let Some(v) = rule.get(i) {
                line.push_str(&format!(",{}", v));
            }
        }

        let digest = md5::compute(line);

        Ok(format!("{:x}", digest))
    }

    fn policy_to_item(
        &self,
        ptype: &str,
        rule: &Vec<String>,
    ) -> Result<HashMap<String, AttributeValue>> {
        let mut item: HashMap<String, AttributeValue> = HashMap::new();

        item.insert("pType".to_string(), AttributeValue::S(ptype.to_string()));

        for i in 0..6 {
            if let Some(v) = rule.get(i) {
                if !v.is_empty() {
                    let key = format!("v{}", i);
                    item.insert(key, AttributeValue::S(v.to_string()));
                }
            }
        }

        let id = self.get_item_id(ptype, &rule)?;
        item.insert("id".to_string(), AttributeValue::S(id));

        Ok(item)
    }

    fn item_to_policy(
        &self,
        item: &HashMap<String, AttributeValue>,
    ) -> Result<(String, Vec<String>)> {
        let mut ptype = "".to_string();
        let mut rule = Vec::new();

        if let Some(att) = item.get("pType") {
            if let Some(v) = att.as_s().ok() {
                ptype = v.to_owned();
            }
        }

        if let Some(att) = item.get("v0") {
            if let Some(v) = att.as_s().ok() {
                rule.push(v.to_owned());
            }
        }

        if let Some(att) = item.get("v1") {
            if let Some(v) = att.as_s().ok() {
                rule.push(v.to_owned());
            }
        }

        if let Some(att) = item.get("v2") {
            if let Some(v) = att.as_s().ok() {
                rule.push(v.to_owned());
            }
        }

        if let Some(att) = item.get("v3") {
            if let Some(v) = att.as_s().ok() {
                rule.push(v.to_owned());
            }
        }

        if let Some(att) = item.get("v4") {
            if let Some(v) = att.as_s().ok() {
                rule.push(v.to_owned());
            }
        }

        if let Some(att) = item.get("v5") {
            if let Some(v) = att.as_s().ok() {
                rule.push(v.to_owned());
            }
        }

        Ok((ptype, rule))
    }

    async fn load_filtered_policy_into_model<'f>(
        &self,
        m: &mut dyn Model,
        f: Filter<'f>,
    ) -> Result<bool> {
        let mut filtered = false;

        let items = self
            .client
            .scan()
            .table_name(&self.table_name)
            .into_paginator()
            .items()
            .send()
            .collect::<std::result::Result<Vec<_>, _>>()
            .await
            .map_err(|e| AdapterError(Box::new(e)))?;

        for item in items {
            let (ptype, policy) = self.item_to_policy(&item)?;
            if ptype.is_empty() || policy.is_empty() {
                return Err(casbin::Error::from(ParsePolicyFailed(
                    "invalid load policy".to_string(),
                )));
            }

            if let Some(sec) = ptype.chars().next() {
                let mut skip_policy = false;

                let f = if sec == 'p' { &f.p } else { &f.g };
                for (i, rule) in f.iter().enumerate() {
                    if !rule.is_empty() && rule != &policy[i] {
                        skip_policy = true;
                        continue;
                    }
                }

                if !skip_policy {
                    m.add_policy(&sec.to_string(), &ptype.to_string(), policy);
                } else {
                    filtered = true;
                }
            }
        }

        Ok(filtered)
    }
}

#[async_trait]
impl Adapter for DynamoDBAdapter {
    async fn load_policy(&self, m: &mut dyn Model) -> Result<()> {
        self.load_filtered_policy_into_model(
            m,
            Filter {
                p: Vec::new(),
                g: Vec::new(),
            },
        )
        .await?;

        Ok(())
    }

    async fn load_filtered_policy<'f>(&mut self, m: &mut dyn Model, f: Filter<'f>) -> Result<()> {
        self.is_filtered = self.load_filtered_policy_into_model(m, f).await?;

        Ok(())
    }

    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        let mut items = Vec::new();
        for sec in vec!["p", "g"] {
            if let Some(ast_map) = m.get_model().get(sec) {
                for (ptype, ast) in ast_map {
                    for rule in ast.get_policy() {
                        let item = self.policy_to_item(ptype, rule)?;
                        items.push(item);
                    }
                }
            }
        }

        if items.is_empty() {
            return Ok(());
        }

        let pages = (items.len() / 25) + 1;
        for page in 0..pages {
            let mut vec: Vec<WriteRequest> = Vec::new();

            let x = page * 25;
            let y = if x + 25 >= items.len() {
                items.len()
            } else {
                x + 25
            };
            for i in x..y {
                if let Some(item) = items.get(i) {
                    vec.push(
                        WriteRequest::builder()
                            .put_request(
                                PutRequest::builder()
                                    .set_item(Some(item.to_owned()))
                                    .build(),
                            )
                            .build(),
                    );
                }
            }

            let mut request: HashMap<String, Vec<WriteRequest>> = HashMap::new();
            request.insert(self.table_name.to_string(), vec);
            self.client
                .batch_write_item()
                .set_request_items(Some(request))
                .send()
                .await
                .map_err(|e| AdapterError(Box::new(e)))?;
        }

        Ok(())
    }

    async fn clear_policy(&mut self) -> Result<()> {
        let items = self
            .client
            .scan()
            .table_name(&self.table_name)
            .into_paginator()
            .items()
            .send()
            .collect::<std::result::Result<Vec<_>, _>>()
            .await
            .map_err(|e| AdapterError(Box::new(e)))?;

        let mut ids: Vec<String> = Vec::new();
        for item in items {
            if let Some(att) = item.get("id") {
                if let Some(v) = att.as_s().ok() {
                    ids.push(v.to_owned());
                }
            }
        }

        if ids.is_empty() {
            return Ok(());
        }

        let pages = (ids.len() / 25) + 1;
        for page in 0..pages {
            let mut vec: Vec<WriteRequest> = Vec::new();

            let x = page * 25;
            let y = if x + 25 >= ids.len() {
                ids.len()
            } else {
                x + 25
            };
            for i in x..y {
                if let Some(id) = ids.get(i) {
                    vec.push(
                        WriteRequest::builder()
                            .delete_request(
                                DeleteRequest::builder()
                                    .key("id", AttributeValue::S(id.to_owned()))
                                    .build(),
                            )
                            .build(),
                    );
                }
            }

            let mut request: HashMap<String, Vec<WriteRequest>> = HashMap::new();
            request.insert(self.table_name.to_string(), vec);
            self.client
                .batch_write_item()
                .set_request_items(Some(request))
                .send()
                .await
                .map_err(|e| AdapterError(Box::new(e)))?;
        }

        Ok(())
    }

    fn is_filtered(&self) -> bool {
        self.is_filtered
    }

    async fn add_policy(&mut self, _sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool> {
        let item = self.policy_to_item(ptype, &rule)?;

        self.client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .send()
            .await
            .map_err(|e| AdapterError(Box::new(e)))?;

        Ok(true)
    }

    async fn add_policies(
        &mut self,
        _sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        if rules.is_empty() {
            return Ok(false);
        }

        let pages = (rules.len() / 25) + 1;
        for page in 0..pages {
            let mut vec: Vec<WriteRequest> = Vec::new();

            let x = page * 25;
            let y = if x + 25 >= rules.len() {
                rules.len()
            } else {
                x + 25
            };
            for i in x..y {
                if let Some(rule) = rules.get(i) {
                    let item = self.policy_to_item(ptype, rule)?;
                    vec.push(
                        WriteRequest::builder()
                            .put_request(PutRequest::builder().set_item(Some(item)).build())
                            .build(),
                    );
                }
            }

            let mut request: HashMap<String, Vec<WriteRequest>> = HashMap::new();
            request.insert(self.table_name.to_string(), vec);
            self.client
                .batch_write_item()
                .set_request_items(Some(request))
                .send()
                .await
                .map_err(|e| AdapterError(Box::new(e)))?;
        }

        Ok(true)
    }

    async fn remove_policy(&mut self, _sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool> {
        let id = self.get_item_id(ptype, &rule)?;

        let res = self
            .client
            .delete_item()
            .table_name(&self.table_name)
            .key("id", AttributeValue::S(id.to_string()))
            .return_values(ReturnValue::AllOld)
            .send()
            .await
            .map_err(|e| AdapterError(Box::new(e)))?;

        if let Some(_v) = res.attributes() {
            return Ok(true);
        }

        Ok(false)
    }

    async fn remove_policies(
        &mut self,
        _sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        if rules.is_empty() {
            return Ok(false);
        }

        let pages = (rules.len() / 25) + 1;
        for page in 0..pages {
            let mut vec: Vec<WriteRequest> = Vec::new();

            let x = page * 25;
            let y = if x + 25 >= rules.len() {
                rules.len()
            } else {
                x + 25
            };
            for i in x..y {
                if let Some(rule) = rules.get(i) {
                    let id = self.get_item_id(ptype, rule)?;
                    vec.push(
                        WriteRequest::builder()
                            .delete_request(
                                DeleteRequest::builder()
                                    .key("id", AttributeValue::S(id))
                                    .build(),
                            )
                            .build(),
                    );
                }
            }

            let mut request: HashMap<String, Vec<WriteRequest>> = HashMap::new();
            request.insert(self.table_name.to_string(), vec);
            self.client
                .batch_write_item()
                .set_request_items(Some(request))
                .send()
                .await
                .map_err(|e| AdapterError(Box::new(e)))?;
        }

        Ok(true)
    }

    async fn remove_filtered_policy(
        &mut self,
        _sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        if field_values.is_empty() {
            return Ok(false);
        }

        let mut names = HashMap::new();
        let mut values = HashMap::new();

        let mut filter = String::from("#pType = :pType");
        names.insert("#pType".to_string(), "pType".to_string());
        values.insert(":pType".to_string(), AttributeValue::S(ptype.to_string()));

        for (pos, val) in field_values.iter().enumerate() {
            let i = field_index + pos;
            if !val.is_empty() {
                let key = format!("v{}", i);
                filter.push_str(&format!(" AND #{} = :{}", key, key));
                names.insert(format!("#{}", key), key.to_string());
                values.insert(format!(":{}", key), AttributeValue::S(val.to_string()));
            }
        }

        let items = self
            .client
            .scan()
            .table_name(&self.table_name)
            .set_filter_expression(Some(filter))
            .set_expression_attribute_names(Some(names))
            .set_expression_attribute_values(Some(values))
            .into_paginator()
            .items()
            .send()
            .collect::<std::result::Result<Vec<_>, _>>()
            .await
            .map_err(|e| AdapterError(Box::new(e)))?;

        let mut ids: Vec<String> = Vec::new();
        for item in items {
            if let Some(att) = item.get("id") {
                if let Some(v) = att.as_s().ok() {
                    ids.push(v.to_owned());
                }
            }
        }

        if ids.is_empty() {
            return Ok(false);
        }

        let pages = (ids.len() / 25) + 1;
        for page in 0..pages {
            let mut vec: Vec<WriteRequest> = Vec::new();

            let x = page * 25;
            let y = if x + 25 >= ids.len() {
                ids.len()
            } else {
                x + 25
            };
            for i in x..y {
                if let Some(id) = ids.get(i) {
                    vec.push(
                        WriteRequest::builder()
                            .delete_request(
                                DeleteRequest::builder()
                                    .key("id", AttributeValue::S(id.to_owned()))
                                    .build(),
                            )
                            .build(),
                    );
                }
            }

            let mut request: HashMap<String, Vec<WriteRequest>> = HashMap::new();
            request.insert(self.table_name.to_string(), vec);
            self.client
                .batch_write_item()
                .set_request_items(Some(request))
                .send()
                .await
                .map_err(|e| AdapterError(Box::new(e)))?;
        }

        Ok(true)
    }
}
