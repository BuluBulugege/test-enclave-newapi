# 04 — Frontend for Official-Channel Badging & Attestation

> Scope: the **frontend surface** for the two provable CC properties. This doc
> specifies (1) an admin "官方直连 / Official" badge on channels, (2) a
> buyer/end-user "attested official" indicator on the marketplace/model
> consumer surface, (3) an admin "Confidential Computing / Attestation" panel,
> and (4) the i18n keys these introduce. It is a **spec + component sketch**;
> it does not edit code.
>
> Companion docs: backend `is_official` derivation and the `/attestation`
> endpoint shape are defined in `02-ratls-attestation.md`; the client verifier
> (linked from the admin panel) is `07-client-verifier.md`.

---

## 0. Load-bearing principles for this frontend

Two rules constrain every choice below, both inherited from doc 07 §0:

1. **The badge and the indicator are convenience, not proof.** Anything the
   gateway renders about its own trustworthiness is served by the gateway and
   can be faked by a subverted gateway. So the admin panel and the buyer
   indicator must always route the *actual trust decision* to the independent
   client verifier (doc 07), and the copy must say so honestly. The UI states
   "this is what the server claims" and links out to "verify it yourself."
2. **Read backend-derived flags; never recompute trust client-side.** The
   `is_official` flag is derived on the backend (blank/official `base_url` +
   no proxy). The frontend reads `channel.is_official` as an opaque boolean. It
   must **not** re-derive officialness by inspecting `base_url`/`proxy` in the
   browser — that would duplicate (and eventually drift from) the backend rule,
   and it would invite the "recompute green client-side" anti-pattern.

---

## 1. Admin "官方直连 / Official" badge on channels

### 1.1 Backend field the frontend consumes

The channel list/detail responses gain a backend-derived boolean. Add it to the
Zod schema in
`web/default/src/features/channels/types.ts` (`channelSchema`), so every
`Channel` carries it and it survives parsing:

```ts
// in channelSchema, near status/base_url
is_official: z.boolean().default(false),
```

`Channel` is `z.infer<typeof channelSchema>`, so `channel.is_official` becomes
available everywhere without a second type. No other type edits are required.
The frontend treats this field as read-only truth from the backend; it is never
set from a form.

### 1.2 Where the channel row is rendered — the Name column

The channel **table** is column-driven. Rows are built from column defs in:

- `web/default/src/features/channels/components/channels-columns.tsx`
  (`useChannelsColumns`) — this is the single source for every cell.

The **card view** (`channel-card.tsx`) does **not** re-implement cells; it calls
`flexRender` on the same column defs (`renderCell('name')`, `renderCell('type')`,
etc.). So a badge added inside the Name column's `cell` renderer appears in
**both** the table and the card automatically. This is the correct, single
insertion point.

The Name cell (regular-channel branch, currently around lines 622–686) already
renders a horizontal row of inline markers next to the name: the pass-through
`AlertTriangle`, the `param_override` `SlidersHorizontal`, and
`<UpstreamUpdateTags />`. The Official badge joins that same marker row, placed
first (leftmost) so it reads as a property of the channel identity.

### 1.3 JSX sketch — Official badge in the Name cell

Reuse the existing `StatusBadge` (Base UI + Tailwind, already imported in
`channels-columns.tsx`) with `variant='success'` (maps to `bg-success`, the
tertiary green `#2D9B4E` in the neo-brutalism palette — the natural "verified /
good" tone) and wrap it in the same `Tooltip` pattern used by the sibling
markers. It is decorative-with-text, so it carries an explanatory tooltip rather
than being click-through.

```tsx
// channels-columns.tsx — inside the Name column cell, regular-channel branch,
// as the FIRST child of the existing marker row:
//   <div className='flex max-w-full min-w-0 items-center gap-1.5'>
//     <TruncatedText ... />
//     {channel.is_official && <OfficialChannelBadge />}   // <-- new, leftmost
//     {isPassThrough && ( ... )}
//     {hasParamOverride && ( ... )}
//     <UpstreamUpdateTags channel={channel} />
//   </div>

function OfficialChannelBadge() {
  const { t } = useTranslation()
  return (
    <TooltipProvider delay={100}>
      <Tooltip>
        <TooltipTrigger
          render={
            <StatusBadge
              label={t('Official')}
              variant='success'
              size='sm'
              copyable={false}
              showDot={false}
              className='shrink-0 cursor-help'
            />
          }
        />
        <TooltipContent side='top' className='max-w-xs'>
          {t(
            'Official direct connection: this channel uses the official base URL with no proxy and runs inside the attested no-log enclave.'
          )}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}
```

Notes:
- `t('Official')` is the visible label. Chinese renders as "官方直连" via the
  locale files (§4), matching the task's "官方直连 / Official" wording.
- `variant='success'` keeps the bold green pill consistent with the existing
  `StatusBadge` neo-brutal styling (solid fill, hard edges). No custom CSS.
- Because this lives in the shared column def, the card view picks it up through
  `renderCell('name')` with zero card-specific code. Confirmed by reading
  `channel-card.tsx`: `nameCell = renderCell('name')` is rendered verbatim.
- Guard strictly on `channel.is_official`; do not fall back to inspecting
  `base_url`. Tag-aggregate rows (`isTagAggregateRow`) skip this branch already.

### 1.4 Optional reinforcement in the channel editor drawer

The editor drawer is
`web/default/src/features/channels/components/drawers/channel-mutate-drawer.tsx`,
whose Basic-Information section header component is
`.../drawers/sections/channel-basic-section.tsx` (`ChannelBasicSection`).

`is_official` is **read-only / backend-derived**, so it must not become a form
field. When editing an existing official channel (`currentRow?.is_official`),
show a non-editable inline note under the Basic Information header so the admin
understands why this channel is special and cannot toggle it here:

```tsx
// inside ChannelMutateDrawer, in the identity/basic section, only when editing:
{isEditing && currentRow?.is_official && (
  <Alert className='border-success/40'>
    <AlertDescription className='text-xs'>
      {t(
        'This is an official direct-connection channel (official base URL, no proxy). Officialness is derived by the server and cannot be edited here.'
      )}
    </AlertDescription>
  </Alert>
)}
```

`Alert`/`AlertDescription` are already imported in the drawer. This is optional
polish; the table/card badge (§1.3) is the required deliverable.

---

## 2. Buyer / end-user "attested official" indicator

### 2.1 Where buyers see channels

End users never see raw channels; they see **models** on the pricing/marketplace
surface:

- Feature: `web/default/src/features/pricing/`
- Card: `web/default/src/features/pricing/components/model-card.tsx`
- Detail drawer: `web/default/src/features/pricing/components/model-details.tsx`
  (+ `model-details-api.tsx`, which already has an `AuthSection`)
- Public route: `web/default/src/routes/pricing/$modelId.tsx`

A model may be served by several channels; "official" is a per-channel property.
The buyer-facing concept is therefore **"this model is available via an attested
official no-log enclave channel"** — a model-level rollup of `is_official`
across the model's serving channels, computed on the backend and exposed on the
pricing/model payload (e.g. `PricingModel.has_official_channel: boolean` in
`features/pricing/types.ts`, alongside the existing `vendor_*` fields). The
frontend, again, reads this as an opaque backend flag.

### 2.2 Indicator concept

Two coordinated placements, both convenience-not-proof:

1. **Model card badge** (`model-card.tsx`): a compact green "Attested official"
   pill next to the model/vendor name, mirroring the admin badge's tone so the
   visual language is consistent across surfaces. On the card it is glanceable
   and non-interactive (tooltip only).

2. **Model detail — a dedicated "Confidential no-log" callout** in
   `model-details.tsx` (a new small section near the existing capability/auth
   blocks, or folded into `model-details-api.tsx`'s `AuthSection`). This is the
   honest, expanded version: it explains what "attested official + no-log
   enclave" means and gives the buyer the **only** trustworthy action — a link
   to independently verify (doc 07 client verifier), plus a link to the admin
   `/attestation` data for the curious. Critically the copy states that the
   badge itself is a server claim and that real assurance comes from running the
   verifier.

```tsx
// model-details.tsx — new callout section, shown when has_official_channel:
{props.model.has_official_channel && (
  <section>
    <SectionTitle>{t('Confidential & official')}</SectionTitle>
    <div className='border-success/40 bg-success/5 flex items-start gap-2 rounded-lg border p-3'>
      <ShieldCheck className='text-success mt-0.5 size-4 shrink-0' aria-hidden='true' />
      <div className='space-y-1.5 text-xs leading-relaxed'>
        <p className='font-medium'>
          {t('Served via an attested official, no-log enclave')}
        </p>
        <p className='text-muted-foreground'>
          {t(
            'Official channels use the provider’s real upstream with no proxy, and run inside an SGX enclave that stores no request or response content. This label reflects what the server reports.'
          )}
        </p>
        <p className='text-muted-foreground'>
          {t(
            'Do not take our word for it: verify the enclave yourself before you trust it.'
          )}
        </p>
        <a
          href='https://<independent-verifier-host>/verify'  // doc 07 verifier
          target='_blank'
          rel='noopener noreferrer'
          className='text-success inline-flex items-center gap-1 font-medium underline underline-offset-2'
        >
          {t('Verify this enclave independently')}
          <ExternalLink className='size-3' aria-hidden='true' />
        </a>
      </div>
    </div>
  </section>
)}
```

Notes:
- `SectionTitle` already exists in `model-details.tsx`; `ShieldCheck` /
  `ExternalLink` come from `lucide-react` (already the icon lib here).
- The verifier URL must be a **gateway-independent** host (doc 07 §0). It is a
  build-time constant (e.g. from a `VITE_`-prefixed env var), not something the
  buyer view derives from the current origin, so a subverted gateway cannot
  silently point "verify" back at itself.
- The card badge for `model-card.tsx` reuses the same `StatusBadge`
  `variant='success'` pill as §1.3 with label `t('Attested official')` and a
  short tooltip; no new styling primitives.

### 2.3 Honesty guardrail

Never render a green checkmark that implies verification *happened*. The buyer
badge says "official" / "attested official" (a claim), and the detail callout
provides the verify-it-yourself path. This keeps the UI aligned with doc 07:
the gateway-served UI is the convenience layer, the independent verifier is the
trust baseline.

---

## 3. Admin "Confidential Computing / Attestation" panel

### 3.1 Where it lives — a new system-settings section

System settings use a **section-registry** pattern. Each settings area
(`operations`, `security`, `models`, …) has:

- a feature dir `web/default/src/features/system-settings/<area>/`
- a `section-registry.tsx` built via
  `features/system-settings/utils/section-registry` (`createSectionRegistry`)
- an `index.tsx` wiring it into the shared `SettingsPage`
- route files under
  `web/default/src/routes/_authenticated/system-settings/<area>/`
  (`index.tsx` redirect + `$section.tsx`)

The whole `system-settings` route is already gated to `ROLE.SUPER_ADMIN` in
`routes/_authenticated/system-settings/route.tsx`, which is exactly the
audience for enclave attestation. Rather than overload an existing area, add a
**new top-level settings area** dedicated to Confidential Computing. It is a
distinct concept (hardware attestation, not app config) and deserves its own
tab.

**New files (spec):**

- `web/default/src/features/system-settings/confidential-computing/section-registry.tsx`
  — registers one section, e.g. `attestation`:

  ```tsx
  const CC_SECTIONS = [
    {
      id: 'attestation',
      titleKey: 'Attestation',
      build: () => <AttestationSection />,
    },
  ] as const

  const ccRegistry = createSectionRegistry<
    CcSectionId, Record<string, never>, []
  >({
    sections: CC_SECTIONS,
    defaultSection: 'attestation',
    basePath: '/system-settings/confidential-computing',
    urlStyle: 'path',
  })
  ```

- `web/default/src/features/system-settings/confidential-computing/index.tsx`
  — mirrors `operations/index.tsx`, feeding the registry to `SettingsPage`.

- `web/default/src/features/system-settings/confidential-computing/attestation-section.tsx`
  — the panel itself (sketch in §3.3).

- `web/default/src/routes/_authenticated/system-settings/confidential-computing/index.tsx`
  and `.../$section.tsx` — copy the `operations/index.tsx` +
  `operations/$section.tsx` route pair (redirect to default section; validate
  `$section`).

The sidebar entry (`hooks/use-sidebar-data.ts`, which currently points "System
Settings" at `/system-settings/site`) does not need a new item — the settings
sub-nav is generated from registries. If a direct deep link is wanted, add a
child under the existing System Settings nav node pointing at
`/system-settings/confidential-computing/attestation`.

### 3.2 Data source — GET /attestation

The panel reads the enclave attestation endpoint from doc 02. Add a typed
fetcher (e.g. in the new feature's `api.ts` or `features/system-settings/api.ts`)
using the project `api` axios instance and a React Query `useQuery`. Expected
response shape (fields the panel renders):

```ts
interface AttestationResponse {
  attestation_type: 'dcap' | 'epid' | 'none'
  mrenclave: string          // hex
  mrsigner: string           // hex
  isv_prod_id: number
  isv_svn: number
  tcb_status: string         // e.g. 'UpToDate', 'SWHardeningNeeded', 'OutOfDate'
  debug_enclave: boolean     // sgx.debug — MUST be false in production
  quote_generated_at: number // unix seconds, for freshness
  collateral_expires_at?: number
  quote?: string             // base64 DCAP quote (for download / verifier)
}
```

The frontend does **not** verify the quote (doc 07 §0: no self-attestation). It
displays the server's claimed measurements and freshness, flags obvious risk
signals (debug enclave, stale/expired collateral, non-`UpToDate` TCB, type ≠
`dcap`), and pushes the actual verification to the external verifier.

### 3.3 Panel sketch

Uses `SettingsSection` (`features/system-settings/components/settings-section.tsx`)
for the section frame, `StatusBadge` for status pills, and a copyable mono
readout for measurements. Neo-brutal: bold borders, hard tone via `StatusBadge`.

```tsx
export function AttestationSection() {
  const { t } = useTranslation()
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['attestation'],
    queryFn: getAttestation,
  })

  if (isLoading) return <Skeleton className='h-64 w-full' />
  if (isError || !data) {
    return (
      <Alert className='border-destructive/40'>
        <AlertDescription>
          {t('Could not reach the attestation endpoint. The enclave may be down or misconfigured.')}
        </AlertDescription>
      </Alert>
    )
  }

  const isDcap = data.attestation_type === 'dcap'
  const tcbOk = data.tcb_status === 'UpToDate'
  const now = Date.now() / 1000
  const stale = data.collateral_expires_at
    ? data.collateral_expires_at < now
    : false

  return (
    <SettingsSection
      title={t('Enclave Attestation')}
      description={t('Live remote-attestation state reported by the confidential-computing enclave.')}
    >
      {/* Debug-enclave warning — highest priority */}
      {data.debug_enclave && (
        <Alert className='border-destructive/60'>
          <AlertTriangle className='size-4' aria-hidden='true' />
          <AlertDescription>
            {t('This enclave is running in DEBUG mode (sgx.debug = true). Debug enclaves are NOT confidential and their measurements must not be trusted for production. This must be false in production.')}
          </AlertDescription>
        </Alert>
      )}

      {/* Status row */}
      <div className='flex flex-wrap items-center gap-2'>
        <StatusBadge
          label={isDcap ? t('DCAP attestation') : t('Attestation type: {{type}}', { type: data.attestation_type })}
          variant={isDcap ? 'success' : 'danger'}
          size='sm'
          copyable={false}
        />
        <StatusBadge
          label={t('TCB: {{status}}', { status: data.tcb_status })}
          variant={tcbOk ? 'success' : 'warning'}
          size='sm'
          copyable={false}
        />
        <StatusBadge
          label={stale ? t('Collateral expired') : t('Collateral fresh')}
          variant={stale ? 'danger' : 'neutral'}
          size='sm'
          copyable={false}
        />
      </div>

      {/* Measurements (copyable mono) */}
      <dl className='border-border grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 rounded-lg border p-3 text-sm'>
        <dt className='text-muted-foreground'>MRENCLAVE</dt>
        <dd className='flex items-center gap-1 font-mono break-all'>
          {data.mrenclave}
          <CopyButton value={data.mrenclave} />
        </dd>
        <dt className='text-muted-foreground'>MRSIGNER</dt>
        <dd className='flex items-center gap-1 font-mono break-all'>
          {data.mrsigner}
          <CopyButton value={data.mrsigner} />
        </dd>
        <dt className='text-muted-foreground'>{t('Product ID / SVN')}</dt>
        <dd className='font-mono'>{data.isv_prod_id} / {data.isv_svn}</dd>
        <dt className='text-muted-foreground'>{t('Quote generated')}</dt>
        <dd>{formatUnixTime(data.quote_generated_at)}</dd>
      </dl>

      {/* Freshness + refresh */}
      <div className='flex items-center gap-2'>
        <span className='text-muted-foreground text-xs'>
          {t('Attestation freshness')}: {formatRelativeTime(data.quote_generated_at, locale)}
        </span>
        <Button variant='outline' size='sm' onClick={() => refetch()}>
          <RefreshCw className='size-3.5' aria-hidden='true' />
          {t('Refresh attestation')}
        </Button>
      </div>

      {/* The honest bit: verify independently */}
      <Alert className='border-info/40'>
        <AlertDescription className='space-y-2 text-xs'>
          <p>
            {t('These values are reported by the server. A subverted gateway can lie about them. Real assurance comes from verifying the DCAP quote yourself against Intel-rooted collateral and a pinned MRENCLAVE.')}
          </p>
          <Button variant='outline' size='sm' render={
            <a href='https://<independent-verifier-host>/verify' target='_blank' rel='noopener noreferrer' />
          }>
            {t('Open the client verifier')}
            <ExternalLink className='size-3.5' aria-hidden='true' />
          </Button>
        </AlertDescription>
      </Alert>
    </SettingsSection>
  )
}
```

Notes:
- `CopyButton` (`@/components/copy-button`), `Skeleton`, `Alert`,
  `StatusBadge`, `Button` are existing components. `formatRelativeTime` /
  `formatTimestampToDate` patterns already exist in the channels lib and
  `@/lib/format`.
- Risk signals map to tone: debug-enclave → destructive Alert (top);
  type≠dcap → danger; TCB≠UpToDate → warning; expired collateral → danger.
- The verifier link is the same gateway-independent constant as §2.2 and points
  at doc 07's verifier. It is the panel's primary trust action; the panel itself
  makes **no** verification claim.

---

## 4. New i18n keys (English source strings)

Flat JSON, English string = key, added to
`web/default/src/i18n/locales/{lang}.json` (zh must render 官方直连 wording).

Admin channel badge (§1):
- `Official`  (zh: 官方直连)
- `Official direct connection: this channel uses the official base URL with no proxy and runs inside the attested no-log enclave.`
- `This is an official direct-connection channel (official base URL, no proxy). Officialness is derived by the server and cannot be edited here.`

Buyer / model indicator (§2):
- `Attested official`
- `Confidential & official`
- `Served via an attested official, no-log enclave`
- `Official channels use the provider’s real upstream with no proxy, and run inside an SGX enclave that stores no request or response content. This label reflects what the server reports.`
- `Do not take our word for it: verify the enclave yourself before you trust it.`
- `Verify this enclave independently`

Attestation panel (§3):
- `Attestation`
- `Confidential Computing`
- `Enclave Attestation`
- `Live remote-attestation state reported by the confidential-computing enclave.`
- `Could not reach the attestation endpoint. The enclave may be down or misconfigured.`
- `DCAP attestation`
- `Attestation type: {{type}}`
- `TCB: {{status}}`
- `Collateral expired`
- `Collateral fresh`
- `This enclave is running in DEBUG mode (sgx.debug = true). Debug enclaves are NOT confidential and their measurements must not be trusted for production. This must be false in production.`
- `Product ID / SVN`
- `Quote generated`
- `Attestation freshness`
- `Refresh attestation`
- `These values are reported by the server. A subverted gateway can lie about them. Real assurance comes from verifying the DCAP quote yourself against Intel-rooted collateral and a pinned MRENCLAVE.`
- `Open the client verifier`

---

## 5. File-touch summary

| Purpose | File (under `web/default/src` unless noted) | Change |
|---|---|---|
| Read `is_official` | `features/channels/types.ts` | add `is_official` to `channelSchema` |
| Admin badge (table + card) | `features/channels/components/channels-columns.tsx` | `OfficialChannelBadge` in Name cell marker row |
| Editor note (optional) | `features/channels/components/drawers/channel-mutate-drawer.tsx` | read-only Alert when `currentRow?.is_official` |
| Buyer rollup flag | `features/pricing/types.ts` | add `has_official_channel` to `PricingModel` |
| Buyer card badge | `features/pricing/components/model-card.tsx` | `StatusBadge` "Attested official" |
| Buyer detail callout | `features/pricing/components/model-details.tsx` | "Confidential & official" section + verifier link |
| Attestation data | `features/system-settings/confidential-computing/api.ts` (new) | `getAttestation` + `AttestationResponse` type |
| Attestation panel | `features/system-settings/confidential-computing/attestation-section.tsx` (new) | panel per §3.3 |
| Settings section registry | `features/system-settings/confidential-computing/section-registry.tsx` (new) | one `attestation` section |
| Settings page wiring | `features/system-settings/confidential-computing/index.tsx` (new) | `SettingsPage` wiring |
| Routes | `routes/_authenticated/system-settings/confidential-computing/{index,$section}.tsx` (new) | copy operations route pair |
| i18n | `i18n/locales/{en,zh,fr,ru,ja,vi}.json` | keys in §4 |

All components reuse existing primitives (`StatusBadge`, `Tooltip`, `Alert`,
`SettingsSection`, `CopyButton`, `Button`, `Skeleton`, lucide icons); no new
styling system is introduced, and every trust decision is delegated to the
independent verifier of doc 07.
