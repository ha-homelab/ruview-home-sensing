# Configuration boundary

`plugin-catalog.json` describes upstream module names and wire capabilities only.
It contains no runtime inventory or installation qualification. A module's
presence in the catalog does not mean it has been enabled or validated.

Runtime site context, installation policy, node inventory, placements, private
UI configuration and approved package manifests are external inputs. Keep their
independent approval hashes separately from candidate files. Test fixtures use
independently fictional neutral zones and must never become production defaults.
