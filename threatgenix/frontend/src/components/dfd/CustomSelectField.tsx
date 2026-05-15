import { useEffect, useMemo, useRef, useState } from "react";

export type CustomSelectOption = {
  value: string;
  label: string;
};

export const CUSTOM_SELECT_SENTINEL = "__custom__";

function isKnownOptionValue(value: string | undefined, options: CustomSelectOption[]): boolean {
  if (!value) {
    return false;
  }
  return options.some((option) => option.value === value);
}

export interface CustomSelectFieldProps {
  id: string;
  label: string;
  value?: string;
  options: CustomSelectOption[];
  onChange: (value: string | undefined) => void;
  disabled?: boolean;
  allowEmpty?: boolean;
  emptyOptionLabel?: string;
  emptyValue?: string;
  customOptionLabel?: string;
  customPlaceholder?: string;
  onCustomModeChange?: (isCustom: boolean) => void;
}

export function CustomSelectField({
  id,
  label,
  value,
  options,
  onChange,
  disabled = false,
  allowEmpty = true,
  emptyOptionLabel = "-- Not set --",
  emptyValue = "",
  customOptionLabel = "Custom...",
  customPlaceholder = "Enter a custom value",
  onCustomModeChange,
}: CustomSelectFieldProps): JSX.Element {
  const externalCustomValue = value?.trim() && !isKnownOptionValue(value, options) ? value.trim() : "";
  const [customMode, setCustomMode] = useState(Boolean(externalCustomValue));
  const [customValue, setCustomValue] = useState(externalCustomValue);
  const customModeChangeRef = useRef(onCustomModeChange);

  useEffect(() => {
    customModeChangeRef.current = onCustomModeChange;
  }, [onCustomModeChange]);

  useEffect(() => {
    const nextCustomMode = Boolean(externalCustomValue);
    setCustomMode(nextCustomMode);
    setCustomValue(externalCustomValue);
    customModeChangeRef.current?.(nextCustomMode);
  }, [externalCustomValue]);

  const selectValue = useMemo(() => {
    if (customMode) {
      return CUSTOM_SELECT_SENTINEL;
    }
    if (value) {
      return value;
    }
    return emptyValue;
  }, [customMode, emptyValue, value]);

  return (
    <div className="form-field">
      <label htmlFor={id}>{label}</label>
      <select
        id={id}
        value={selectValue}
        onChange={(event) => {
          const nextValue = event.target.value;
          if (nextValue === CUSTOM_SELECT_SENTINEL) {
            setCustomMode(true);
            setCustomValue(externalCustomValue);
            onCustomModeChange?.(true);
            return;
          }
          setCustomMode(false);
          onCustomModeChange?.(false);
          onChange(nextValue === emptyValue ? undefined : nextValue);
        }}
        disabled={disabled}
      >
        {allowEmpty ? <option value={emptyValue}>{emptyOptionLabel}</option> : null}
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
        <option value={CUSTOM_SELECT_SENTINEL}>{customOptionLabel}</option>
      </select>
      {customMode ? (
        <input
          id={`${id}-custom`}
          className="dfd-custom-select-input"
          type="text"
          value={customValue}
          onChange={(event) => {
            const nextValue = event.target.value;
            setCustomValue(nextValue);
            onChange(nextValue.trim() || undefined);
          }}
          placeholder={customPlaceholder}
          disabled={disabled}
        />
      ) : null}
    </div>
  );
}
