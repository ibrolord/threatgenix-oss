import { useEffect, useState } from "react";
import { api } from "../api/client";

interface ProviderOption {
  name: string;
  display_name: string;
  default_model: string;
}

export default function ModelSelector() {
  const [providers, setProviders] = useState<ProviderOption[]>([]);
  const [providerModels, setProviderModels] = useState<Record<string, string[]>>({});
  const [activeProvider, setActiveProvider] = useState("");
  const [activeModel, setActiveModel] = useState("");
  const [switching, setSwitching] = useState(false);
  const [loadingModels, setLoadingModels] = useState(false);
  const [error, setError] = useState("");

  async function loadProviderModels(provider: string, fallbackModel?: string) {
    if (!provider) return;
    if (providerModels[provider]?.length) return;
    setLoadingModels(true);
    try {
      const data = await api.getLLMProviderModels(provider);
      const models = Array.from(
        new Set(
          [fallbackModel, ...data.models].filter(
            (model): model is string => Boolean(model) && model !== "not initialized"
          )
        )
      );
      setProviderModels((current) => ({ ...current, [provider]: models }));
    } catch (err) {
      if (fallbackModel && fallbackModel !== "not initialized") {
        setProviderModels((current) => ({ ...current, [provider]: [fallbackModel] }));
      }
      setError(err instanceof Error ? err.message : "Failed to load provider models");
    } finally {
      setLoadingModels(false);
    }
  }

  useEffect(() => {
    api
      .getLLMProviders()
      .then((data) => {
        setProviders(data.available);
        const selectedProvider = data.available.some((provider) => provider.name === data.active.provider)
          ? data.active.provider
          : data.available[0]?.name ?? "";
        setActiveProvider(selectedProvider);
        setActiveModel(data.active.model);
        void loadProviderModels(selectedProvider, data.active.model);
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : "Failed to load AI providers");
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const newProvider = e.target.value;
    if (newProvider === activeProvider) return;

    setSwitching(true);
    setError("");

    const match = providers.find((p) => p.name === newProvider);

    try {
      await loadProviderModels(newProvider, match?.default_model);
      const result = await api.switchLLMProvider(
        newProvider,
        match?.default_model
      );
      setActiveProvider(result.provider);
      setActiveModel(result.model);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Switch failed");
      // revert the select to previous value — active state unchanged
    } finally {
      setSwitching(false);
    }
  }

  async function handleModelChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const newModel = e.target.value;
    if (!activeProvider || newModel === activeModel) return;

    setSwitching(true);
    setError("");

    try {
      const result = await api.switchLLMProvider(activeProvider, newModel);
      setActiveProvider(result.provider);
      setActiveModel(result.model);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Switch failed");
    } finally {
      setSwitching(false);
    }
  }

  if (providers.length <= 1) {
    return error ? (
      <div className="model-selector" role="status">
        <span className="model-selector-error" title={error}>AI provider unavailable</span>
      </div>
    ) : null;
  }

  const activeModels = providerModels[activeProvider] ?? (
    activeModel && activeModel !== "not initialized" ? [activeModel] : []
  );
  const modelOptions = activeModel && !activeModels.includes(activeModel)
    ? [activeModel, ...activeModels]
    : activeModels;

  return (
    <div className="model-selector">
      <label className="model-selector-label" htmlFor="llm-provider-select">
        AI:
      </label>
      <select
        id="llm-provider-select"
        className="model-selector-select"
        value={activeProvider}
        onChange={handleChange}
        disabled={switching}
        title="Switch the active AI provider used for generation, review, and explanation flows"
      >
        {providers.map((p) => (
          <option key={p.name} value={p.name}>
            {p.display_name}
          </option>
        ))}
      </select>
      {modelOptions.length > 1 ? (
        <select
          id="llm-model-select"
          className="model-selector-select model-selector-model-select"
          value={activeModel}
          onChange={handleModelChange}
          disabled={switching || loadingModels}
          title="Switch the active AI model for generation, review, and explanation flows"
        >
          {modelOptions.map((model) => (
            <option key={model} value={model}>
              {model}
            </option>
          ))}
        </select>
      ) : activeModel && !switching && activeModel !== "not initialized" ? (
        <span className="model-selector-model" title={`Current active model: ${activeModel}`}>{activeModel}</span>
      ) : null}
      {loadingModels && !switching && (
        <span className="model-selector-model">Loading models</span>
      )}
      {switching && <span className="model-selector-spinner" />}
      {error && <span className="model-selector-error" title={error}>!</span>}
    </div>
  );
}
