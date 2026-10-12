// The application bridge forwards draws and type-backs without retaining phrase material.
const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('aukoraAumlok', {
  available: true,
  /** The shell's public state: the adapter's binding and the signing session's status. */
  state: () => ipcRenderer.invoke('aumlok:approval:state'),
  /**
   * Draw the seven words for one ceremony, once, for display on this page.
   * @param {string} intent - which ceremony is being started: `bind` or `refresh`.
   * @returns {Promise<{ok: boolean, words?: string[], reason?: string}>} the words, or the shell's
   *   own reason. The words are in order, anchor first, and are seven lower-case words or nothing.
   */
  draw: (intent, language = 'en') => ipcRenderer.invoke('aumlok:approval:draw', { intent, language }),
  /**
   * Hand the typed words back and resolve with the shell's verdict.
   *
   * THE HANDLE CROSSES WITH THE WORDS, AND IT IS NOT A SECRET. X8 derives the key from the handle and
   * the seven words together, so the second half of the key travels the same way the first does: typed
   * on this page, passed through as typed, kept nowhere here. It is public — it is recorded in the
   * public record and it is what a NIP-05 `name@domain` local part is read from — so nothing on this
   * path has to protect it; the words beside it are the half that must not be logged.
   * @param {string} intent - which ceremony the words belong to.
   * @param {readonly string[]} words - the seven typed words, in order, anchor first.
   * @param {string|undefined} handle - the person's public handle, as typed.
   * @returns {Promise<{ok: boolean, reason?: string}>} whether the words were the ones drawn, and the
   *   shell's own reason when they were not. NO REPLY ON THIS PATH CARRIES A PHRASE BYTE.
   */
  submit: (intent, words, handle) =>
    ipcRenderer.invoke('aumlok:approval:submit', { intent, words, handle }),
})
