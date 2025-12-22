// api/verify.js
export default async function handler(req, res) {
  // 1. Autoriser l'accès depuis n'importe où (CORS) - Important pour une extension
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  // Gérer la requête préliminaire du navigateur (OPTIONS)
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  // 2. Vérifier que c'est bien une requête POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { license_key } = req.body;

  if (!license_key) {
    return res.status(400).json({ error: 'License key is missing' });
  }

  try {
    // 3. Demander à Gumroad si la clé est valide
    const response = await fetch('https://api.gumroad.com/v2/licenses/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        product_id: process.env.GUMROAD_PRODUCT_ID, // Le secret caché chez Vercel
        license_key: license_key,
        increment_uses_count: "false" // "false" pour éviter de griller une activation à chaque test
      }),
    });

    const data = await response.json();

    // 4. Renvoyer la réponse à l'extension
    if (data.success && !data.purchase.refunded && !data.purchase.chargebacked) {
      return res.status(200).json({ success: true });
    } else {
      return res.status(200).json({ success: false, message: 'Invalid license' });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Server error' });
  }
}
