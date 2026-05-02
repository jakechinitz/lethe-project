//! Retention worker: stale threads and room messages get pruned by
//! `db::retention::run_once`. Tests bypass the worker and call the
//! function directly so they don't need to wait on the tick interval.

mod support;

use lethe_server::db;

#[tokio::test]
async fn deletes_threads_past_retention() {
    let s = support::spawn().await;

    // Tighten retention to zero days for the seeded `general` board so
    // any historic row is immediately stale.
    sqlx::query("UPDATE boards SET retention_days = 0 WHERE id = $1")
        .bind("general")
        .execute(&s.db)
        .await
        .unwrap();

    // Insert a thread with an explicitly old created_at, plus a fresh one.
    sqlx::query(
        "INSERT INTO threads (id, board_id, title, created_at)
         VALUES ($1, 'general', 'old', now() - interval '1 hour')",
    )
    .bind(&[1u8; 16][..])
    .execute(&s.db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO threads (id, board_id, title, created_at)
         VALUES ($1, 'general', 'fresh', now() + interval '1 hour')",
    )
    .bind(&[2u8; 16][..])
    .execute(&s.db)
    .await
    .unwrap();

    let stats = db::retention::run_once(&s.db).await.unwrap();
    assert_eq!(stats.threads_deleted, 1);

    let titles: Vec<(String,)> =
        sqlx::query_as("SELECT title FROM threads ORDER BY title")
            .fetch_all(&s.db)
            .await
            .unwrap();
    assert_eq!(titles.len(), 1);
    assert_eq!(titles[0].0, "fresh");
}

#[tokio::test]
async fn deletes_room_messages_past_retention() {
    let s = support::spawn().await;

    // Stand up a minimal room directly via SQL so we can insert messages
    // with arbitrary timestamps.
    let room_id = vec![9u8; 16];
    sqlx::query(
        "INSERT INTO rooms (id, invite_code, created_at, message_retention_days)
         VALUES ($1, 'inv', now(), 0)",
    )
    .bind(&room_id)
    .execute(&s.db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO room_members
            (room_id, member_box_pubkey, member_sig_pubkey, wrapped_key, joined_at)
         VALUES ($1, $2, $3, $4, now())",
    )
    .bind(&room_id)
    .bind(&[1u8; 32][..])
    .bind(&[1u8; 32][..])
    .bind(&[1u8; 32][..])
    .execute(&s.db)
    .await
    .unwrap();

    // Use explicit timestamps so the fresh row's created_at is strictly
    // greater than `now()` at DELETE time (now() advances between txs).
    for (id, offset) in [(b"old", "-1 hour"), (b"new", "+1 hour")].iter() {
        let mut id_bytes = vec![0u8; 16];
        id_bytes[..3].copy_from_slice(*id);
        sqlx::query(
            "INSERT INTO room_messages
                (id, room_id, sender_sig_pubkey, nonce, ciphertext, sender_sig, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, now() + ($7)::interval)",
        )
        .bind(id_bytes)
        .bind(&room_id)
        .bind(&[1u8; 32][..])
        .bind(&[0u8; 24][..])
        .bind(&[0u8; 32][..])
        .bind(&[0u8; 64][..])
        .bind(*offset)
        .execute(&s.db)
        .await
        .unwrap();
    }

    let stats = db::retention::run_once(&s.db).await.unwrap();
    assert_eq!(stats.room_messages_deleted, 1);

    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM room_messages")
        .fetch_one(&s.db)
        .await
        .unwrap();
    assert_eq!(count.0, 1);
}
