export interface CspOptions {
  [key: string]: string | string[] | undefined; // accepts single or multiple
}

const BASE_DIRECTIVES: Array<[string, string[]]> = [
  ["default-src", ["'self'"]],
  ["script-src", ["'self'", "'unsafe-inline'", "'unsafe-eval'"]],
  ["style-src", ["'self'", "'unsafe-inline'"]],
  ["img-src", ["'self'", "data:", "blob:"]],
  ["connect-src", ["'self'"]],
  ["frame-src", ["'self'"]],
  ["font-src", ["'self'", "https:", "data:"]],
  ["frame-ancestors", ["'self'"]],
  ["form-action", ["'self'"]],
  ["base-uri", ["'self'"]],
  ["object-src", ["'none'"]],
];

function serializeDirectives(directives: Array<[string, Set<string>]>) {
  return directives
    .map(([directive, values]) => `${directive} ${Array.from(values).join(" ")}`)
    .concat("upgrade-insecure-requests")
    .join("; ");
}

export function buildContentSecurityPolicy(options: CspOptions = {}): string {
  const directives = BASE_DIRECTIVES.map(
    ([name, values]) => [name, new Set(values)] as [string, Set<string>],
  );

  // Loop through each passed host entry
  for (const [key, hostOrHosts] of Object.entries(options)) {
    if (!hostOrHosts) continue;

    // Convert single URL → array for uniform handling
    const hosts = Array.isArray(hostOrHosts) ? hostOrHosts : [hostOrHosts];

    for (const host of hosts) {
      for (const [name, values] of directives) {
        // Apply to the most common directives for security
        if (
          name === "script-src" ||
          name === "connect-src" ||
          name === "img-src" ||
          name === "frame-src"
        ) {
          values.add(host);
        }
      }
    }
  }

  return serializeDirectives(directives);
}
