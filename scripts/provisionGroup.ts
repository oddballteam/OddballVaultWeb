/**
 * One-time admin utility: provisions a new Group Folder bound to an
 * existing Okta group, and adds its first admin member.
 *
 * Run server-side only (`node --experimental-global-webcrypto` on Node <20,
 * plain `node` on Node 20+) with SUPABASE_SERVICE_ROLE_KEY in the
 * environment — this key bypasses RLS entirely and must never reach the
 * browser bundle or a client-visible .env file.
 *
 * Usage: npx tsx scripts/provisionGroup.ts <name> <oktaGroupId> <firstAdminEmail>
 *
 * Ongoing membership sync (adding/removing members as Okta group
 * membership changes) is a separate reconciliation job against Okta's
 * Groups API, not built here — see the architecture notes on why that's
 * intentionally out of scope for this pass.
 */
import { createClient } from "@supabase/supabase-js";
import { createGroupKeyMaterial, wrapKekForMember } from "../src/crypto/groupKeys";
import { importPublicKey } from "../src/crypto/rsa";

async function main() {
  const [name, oktaGroupId, firstAdminEmail] = process.argv.slice(2);
  if (!name || !oktaGroupId || !firstAdminEmail) {
    console.error("Usage: provisionGroup.ts <name> <oktaGroupId> <firstAdminEmail>");
    process.exit(1);
  }

  const supabaseUrl = requireEnv("SUPABASE_URL");
  const serviceRoleKey = requireEnv("SUPABASE_SERVICE_ROLE_KEY");
  const supabase = createClient(supabaseUrl, serviceRoleKey);

  const { data: admin, error: adminError } = await supabase
    .from("user_directory")
    .select("id, public_key")
    .eq("email", firstAdminEmail)
    .single();
  if (adminError || !admin) {
    throw new Error(`${firstAdminEmail} must sign in at least once (to register a public key) before being made a group admin.`);
  }

  const material = await createGroupKeyMaterial();
  const { data: group, error: groupError } = await supabase
    .from("groups")
    .insert({
      name,
      okta_group_id: oktaGroupId,
      public_key: material.publicKeySpki,
      encrypted_private_key: material.encryptedPrivateKey,
      private_key_nonce: material.encryptedPrivateKeyNonce,
    })
    .select("id")
    .single();
  if (groupError) throw groupError;

  const adminPublicKey = await importPublicKey(admin.public_key);
  const wrappedKek = await wrapKekForMember(material.kek, adminPublicKey);

  const { error: membershipError } = await supabase.from("group_memberships").insert({
    group_id: group.id,
    user_id: admin.id,
    wrapped_group_kek: wrappedKek,
    role: "admin",
  });
  if (membershipError) throw membershipError;

  console.log(`Provisioned group "${name}" (${group.id}) with ${firstAdminEmail} as admin.`);
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required env var: ${name}`);
  return value;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
