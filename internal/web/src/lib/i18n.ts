import de from '../../messages/de.json';
import en from '../../messages/en.json';

const messages: Record<string, Record<string, string>> = { de, en };

function detectLang(): string {
  if (typeof navigator !== 'undefined') {
    const lang = navigator.language.split('-')[0];
    if (lang === 'de' || lang === 'en') return lang;
  }
  return 'de';
}

const lang = detectLang();

type MessageKey = keyof typeof de;

function t(key: MessageKey): string {
  return messages[lang]?.[key as string] ?? messages['de']?.[key as string] ?? key;
}

export const m = new Proxy({} as Record<MessageKey, () => string>, {
  get(_target, key: string) {
    return () => t(key as MessageKey);
  },
});
