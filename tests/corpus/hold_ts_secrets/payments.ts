const STRIPE_SECRET = "sk_live_51Habcdef0123456789xyz";
const apiKey = process.env.API_KEY;
const PUBLIC_KEY_URL = "https://cdn.example.com/keys/public.pem";

export async function charge(amount: number) {
  return fetch("https://api.stripe.com/v1/charges", {
    method: "POST",
    headers: { Authorization: `Bearer ${STRIPE_SECRET}` },
    body: JSON.stringify({ amount }),
  });
}
