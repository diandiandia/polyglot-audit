export async function getJson(url: string): Promise<unknown> {
  const res = await fetch(url);
  return res.json();
}
