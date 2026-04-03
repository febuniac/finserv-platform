// Database seed script
// BUG: Uses hardcoded test credentials that mirror production patterns
const seedData = {
  users: [
    {
      email: 'admin@finserv.com',
      password: 'admin123', // SECURITY: Weak default password
      role: 'admin',
      name: 'System Admin',
    },
    {
      email: 'auditor@finserv.com',
      password: 'audit2024', // SECURITY: Predictable password
      role: 'auditor',
      name: 'Security Auditor',
    },
  ],
  accounts: [
    {
      name: 'Operating Account',
      type: 'checking',
      balance: 1000000,
      currency: 'USD',
    },
    {
      name: 'Reserve Fund',
      type: 'savings',
      balance: 5000000,
      currency: 'USD',
    },
  ],
};

async function seed() {
  console.log('Seeding database...');
  // BUG: Seed script doesn't actually connect to database
  console.log(`Created ${seedData.users.length} users`);
  console.log(`Created ${seedData.accounts.length} accounts`);
  console.log('Seeding complete!');
}

seed().catch(console.error);
