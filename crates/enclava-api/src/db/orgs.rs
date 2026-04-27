use enclava_common::orgs::generate_org_slug;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

const MAX_SLUG_RETRIES: u32 = 5;

fn is_slug_collision(err: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(db) = err
        && db.code().as_deref() == Some("23505")
    {
        return db.constraint() == Some("organizations_cust_slug_key")
            || db.message().contains("cust_slug");
    }
    false
}

/// Insert a row into `organizations` using a freshly-generated `cust_slug`.
///
/// Retries on `cust_slug` UNIQUE collisions only (other unique violations,
/// e.g. on `name`, propagate). Returns the slug that was committed.
pub async fn insert_org_pool(
    pool: &PgPool,
    id: Uuid,
    name: &str,
    display_name: Option<&str>,
    is_personal: bool,
) -> Result<String, sqlx::Error> {
    for _ in 0..MAX_SLUG_RETRIES {
        let slug = generate_org_slug();
        match sqlx::query(
            "INSERT INTO organizations (id, name, display_name, is_personal, cust_slug)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(name)
        .bind(display_name)
        .bind(is_personal)
        .bind(&slug)
        .execute(pool)
        .await
        {
            Ok(_) => return Ok(slug),
            Err(e) if is_slug_collision(&e) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(sqlx::Error::Protocol(
        "exhausted org_slug retries — too many collisions".into(),
    ))
}

/// Same as `insert_org_pool` but on an open connection (typically a
/// transaction's `&mut *tx`).
pub async fn insert_org_conn(
    conn: &mut PgConnection,
    id: Uuid,
    name: &str,
    display_name: Option<&str>,
    is_personal: bool,
) -> Result<String, sqlx::Error> {
    for _ in 0..MAX_SLUG_RETRIES {
        let slug = generate_org_slug();
        match sqlx::query(
            "INSERT INTO organizations (id, name, display_name, is_personal, cust_slug)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(name)
        .bind(display_name)
        .bind(is_personal)
        .bind(&slug)
        .execute(&mut *conn)
        .await
        {
            Ok(_) => return Ok(slug),
            Err(e) if is_slug_collision(&e) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(sqlx::Error::Protocol(
        "exhausted org_slug retries — too many collisions".into(),
    ))
}
