use mysql_async::*;
use mysql_async::prelude::*;
use tokio;

pub struct AsyncLogInserter {
    pool: Pool,
}

impl AsyncLogInserter {
    pub async fn new(url: &str) -> Result<Self> {
        let opts = Opts::from_url(url)?;
        let pool = Pool::new(opts);
        Ok(Self { pool })
    }

    pub async fn insert(&self, table: &str, columns: &[&str], values: &[&str]) -> Result<()> {
        let mut conn = self.pool.get_conn().await?;

        let placeholders = (0..values.len()).map(|_| "?").collect::<Vec<_>>().join(", ");
        let query = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            table,
            columns.join(", "),
            placeholders
        );

        let params: Vec<Value> = values.iter().map(|&v| v.into()).collect();
        conn.exec_drop(query, params).await?;

        Ok(())
    }
}