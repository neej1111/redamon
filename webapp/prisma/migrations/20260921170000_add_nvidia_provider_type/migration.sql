-- Support NVIDIA NIM as a first-class provider type.
--
-- provider_type is a free-form TEXT column and the schema already carries the
-- apiKey/baseUrl/modelIdentifier fields NVIDIA needs, so no DDL is strictly
-- required. This migration exists to (a) pin the NLP-visible comment on the
-- column documenting 'nvidia' as a recognised type and (b) normalize any
-- pre-existing experimental 'nvidia-nim' / 'nim' rows to the canonical
-- 'nvidia' providerType with the default NIM base URL applied when blank.
-- Both statements are idempotent and no-ops on clean databases.

COMMENT ON COLUMN "user_llm_providers"."provider_type" IS
  'Provider kind: openai | anthropic | openrouter | bedrock | deepseek | gemini | glm | kimi | qwen | xai | mistral | nvidia | openai_compatible';

UPDATE "user_llm_providers"
SET "provider_type" = 'nvidia'
WHERE "provider_type" IN ('nvidia-nim', 'nim', 'nvidia_nim');

UPDATE "user_llm_providers"
SET "base_url" = 'https://integrate.api.nvidia.com/v1'
WHERE "provider_type" = 'nvidia' AND ("base_url" IS NULL OR "base_url" = '');
