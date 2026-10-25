import * as fs from "node:fs";

/** A set of peer ids persisted as a JSON array: ids only, never what anyone said. */
export class IdSet {
  private readonly ids: Set<string>;

  constructor(private readonly file: string) {
    this.ids = new Set(fs.existsSync(file) ? (JSON.parse(fs.readFileSync(file, "utf8")) as string[]) : []);
  }

  has(id: string): boolean {
    return this.ids.has(id);
  }

  add(id: string): void {
    this.ids.add(id);
    this.save();
  }

  delete(id: string): void {
    if (this.ids.delete(id)) this.save();
  }

  private save(): void {
    fs.writeFileSync(this.file, JSON.stringify([...this.ids]), { mode: 0o600 });
  }
}
