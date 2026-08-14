require('dotenv').config();
const { neon } = require('@neondatabase/serverless');

async function check() {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    console.log("No DATABASE_URL found.");
    return;
  }
  const sql = neon(dbUrl);
  try {
    const campaigns = await sql`SELECT id, status, is_ab_test, ab_status, total_sent, success_count, failed_count, array_length(recipient_emails, 1) as recipient_emails_len, array_length(sent_recipients, 1) as sent_recipients_len, error_details, locked_at FROM campaigns ORDER BY sent_at DESC LIMIT 1`;
    console.log("Latest Campaign:");
    console.log(JSON.stringify(campaigns, null, 2));
  } catch (err) {
    console.error(err);
  }
}
check();
