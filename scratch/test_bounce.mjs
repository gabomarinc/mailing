import dotenv from 'dotenv';
dotenv.config();
import { neon } from '@neondatabase/serverless';

const sql = neon(process.env.DATABASE_URL);

async function run() {
  try {
    const stats = await sql`SELECT SUM(bounce_count) as total_bounces, SUM(total_sent) as total_sent_all FROM campaigns`;
    console.log('Campaigns Stats:', stats);
    
    const contacts = await sql`SELECT status, count(*) FROM contacts GROUP BY status`;
    console.log('Contacts Stats:', contacts);
  } catch(e) {
    console.error(e);
  }
  process.exit(0);
}
run();
