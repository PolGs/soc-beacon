declare module "sql.js" {
  export type SqlJsValue = string | number | null | Uint8Array

  export interface Statement {
    bind(values: unknown[]): void
    run(values?: unknown[]): void
    step(): boolean
    getAsObject(): Record<string, unknown>
    free(): void
  }

  export interface Database {
    run(sql: string, params?: unknown[]): void
    exec(sql: string): Array<{ columns: string[]; values: unknown[][] }>
    prepare(sql: string): Statement
    export(): Uint8Array
    close?(): void
  }

  export interface SqlJsStatic {
    Database: new (data?: Uint8Array | ArrayBuffer) => Database
  }

  export default function initSqlJs(config?: Record<string, unknown>): Promise<SqlJsStatic>
}
