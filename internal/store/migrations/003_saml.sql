-- SAML 2.0 service providers. Trust comes from these rows: Keyhaven only
-- sends assertions to an app's registered entity ID and exact ACS URLs.
CREATE TABLE saml_apps (
    id             text PRIMARY KEY,
    name           text NOT NULL,
    entity_id      text NOT NULL UNIQUE,
    acs_urls       text[] NOT NULL,
    name_id_format text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);
