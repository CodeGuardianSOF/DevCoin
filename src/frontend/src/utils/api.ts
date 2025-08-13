export function api({ token }: { token?: string }) {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  return {
    async post(path: string, body: any) {
      const res = await fetch(path, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });
      return res;
    },
  };
}
