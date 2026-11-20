export {};

declare global {
  interface Window {
    __plazaTest: {
      setNotificationMode: (mode: string) => void;
      setBoardsLoaded: (loaded: boolean) => void;
      clearBoards: () => void;
      archiveBoard: (index: number, archived: boolean) => void;
      moveBoard: (index: number, delta: number) => void;
      boardNames: () => [string, boolean][];
      notify: (title: string, body: string) => void;
    };
    __notifications: Array<{
      title: string;
      body?: string;
      tag?: string;
      instance: { onclick: (() => void) | null };
    }>;
  }
}
