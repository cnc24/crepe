//! Closed query helpers for typed IP containment and structured payload fields.
use datafusion::{
    arrow::{
        array::{BooleanArray, StringArray},
        datatypes::DataType,
    },
    logical_expr::{create_udf, ColumnarValue, Volatility},
    prelude::SessionContext,
};
use std::sync::Arc;

pub fn register(ctx: &SessionContext) {
    ctx.register_udf(create_udf(
        "crepe_json",
        vec![DataType::Utf8, DataType::Utf8],
        DataType::Utf8,
        Volatility::Immutable,
        Arc::new(|args| {
            let arrays = ColumnarValue::values_to_arrays(args)?;
            let input = arrays[0]
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or_else(|| {
                    datafusion::error::DataFusionError::Execution("expected UTF8 payload".into())
                })?;
            let paths = arrays[1]
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or_else(|| {
                    datafusion::error::DataFusionError::Execution("expected UTF8 pointer".into())
                })?;
            let out = input
                .iter()
                .zip(paths.iter())
                .map(|(text, path)| {
                    let value: serde_json::Value = serde_json::from_str(text?).ok()?;
                    match value.pointer(path?)? {
                        serde_json::Value::String(s) => Some(s.clone()),
                        serde_json::Value::Number(n) => Some(n.to_string()),
                        serde_json::Value::Bool(b) => Some(b.to_string()),
                        _ => None,
                    }
                })
                .collect::<StringArray>();
            Ok(ColumnarValue::Array(Arc::new(out)))
        }),
    ));
    ctx.register_udf(create_udf(
        "crepe_cidr",
        vec![DataType::Utf8, DataType::Utf8],
        DataType::Boolean,
        Volatility::Immutable,
        Arc::new(|args| {
            let arrays = ColumnarValue::values_to_arrays(args)?;
            let ips = arrays[0]
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or_else(|| {
                    datafusion::error::DataFusionError::Execution("expected UTF8 IP".into())
                })?;
            let networks = arrays[1]
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or_else(|| {
                    datafusion::error::DataFusionError::Execution("expected UTF8 CIDR".into())
                })?;
            let out = ips
                .iter()
                .zip(networks.iter())
                .map(|(ip, net)| {
                    Some(
                        net?.parse::<ipnet::IpNet>()
                            .ok()?
                            .contains(&ip?.parse::<std::net::IpAddr>().ok()?),
                    )
                })
                .collect::<BooleanArray>();
            Ok(ColumnarValue::Array(Arc::new(out)))
        }),
    ));
}
