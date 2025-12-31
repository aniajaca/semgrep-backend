// Development Testing Script - Local environment only
// Context: internet_facing=FALSE, production=FALSE, handles_pii=FALSE

const db = require('../database');

/**
 * Development script for testing database queries
 * Usage: node scripts/test_query.js "search term"
 */

async function testDatabaseQuery() {
  const searchTerm = process.argv[2] || 'default';
  
  console.log('Testing database query with term:', searchTerm);
  
  // VULNERABILITY: SQL Injection - same vulnerability, development context
  const query = `SELECT * FROM test_data WHERE name='${searchTerm}'`;
  
  try {
    const result = await db.query(query);
    console.log('Query results:', result.rows);
    console.log(`Found ${result.rows.length} records`);
  } catch (error) {
    console.error('Query failed:', error.message);
  }
  
  process.exit(0);
}

if (require.main === module) {
  testDatabaseQuery();
}

module.exports = { testDatabaseQuery };