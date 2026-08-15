import { useCallback, useEffect, useRef, useState } from 'react'
import { get, ApiError } from '@/lib/api'

/** Page size options, shared so the two tables offer the same ones. */
export const PAGE_SIZES = ['20', '50', '100', '200']

const DEFAULT_PAGE_SIZE = 50

/** How long a keystroke waits before it becomes a request. */
const SEARCH_DEBOUNCE_MS = 300

interface PageResponse<Row> {
  rows: Row[]
  total: number
}

/**
 * Server-side paging, searching and filtering for the admin tables.
 *
 * The tables used to receive every row inside /admin/api/state and filter them
 * in the browser, which is a fine design for the few hundred codes one site
 * issues and stops working at the scale this portal is now pointed at: fifty
 * thousand codes plus every redemption ever recorded is tens of megabytes per
 * page load, built fresh each time because the response is no-store.
 *
 * Two details worth stating, because both are bugs when they are absent:
 *
 *   - Responses are matched to the request that asked for them. Typing quickly
 *     puts several requests in flight and they do not necessarily come back in
 *     order; without the sequence check the table can settle on the results for
 *     a prefix of what the operator typed.
 *   - Changing the search or the filter resets to page 1. Staying on page 7 of
 *     a result set that now has two pages shows an empty table, which reads as
 *     "nothing matches" rather than "you are past the end".
 */
export function useServerTable<Row, Extra = unknown>(
  path: string,
  params: Record<string, string | number | undefined> = {},
) {
  const [rows, setRows] = useState<Row[]>([])
  const [total, setTotal] = useState(0)
  const [extra, setExtra] = useState<Extra | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE)

  // Serialised so the effect below re-runs on a value change rather than on
  // every render, which an object identity would cause.
  const paramKey = JSON.stringify(params)
  const seq = useRef(0)

  const load = useCallback(async () => {
    const mine = ++seq.current
    setLoading(true)
    try {
      const body = await get<PageResponse<Row> & Extra>(path, {
        offset: (page - 1) * pageSize,
        limit: pageSize,
        ...(JSON.parse(paramKey) as Record<string, string | number | undefined>),
      })
      if (mine !== seq.current) return // A newer request is already in flight.
      setRows(body.rows ?? [])
      setTotal(body.total ?? 0)
      setExtra(body)
      setError(null)
    } catch (err) {
      if (mine !== seq.current) return
      setError(err instanceof ApiError ? err.code : 'error')
    } finally {
      if (mine === seq.current) setLoading(false)
    }
  }, [path, page, pageSize, paramKey])

  useEffect(() => {
    void load()
  }, [load])

  // Any change to the filters puts the operator back on the first page.
  useEffect(() => {
    setPage(1)
  }, [paramKey])

  return {
    rows,
    total,
    extra,
    loading,
    error,
    page,
    pageSize,
    setPage,
    setPageSize,
    reload: load,
  }
}

/** Debounce a value, so a search box makes one request per pause, not per key. */
export function useDebounced<T>(value: T, ms = SEARCH_DEBOUNCE_MS): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), ms)
    return () => clearTimeout(id)
  }, [value, ms])
  return debounced
}
