# v0.0.28

* Added commands `show fund`, `alter fund`, and `drop fund`.

* Removed command `archive project`.

* The `show projects` command now returns the project title.

* Added `create filter` and `show filters` commands and `filter()`
  operator.

* Added experimental input validator `ccms.Validator`.

# v0.0.27

* Added `Error()` and `ErrorIndex()` functions to `ccms.Response`.

* Added the attribute `decision`.

* Added the `select version()` command.

# v0.0.26

* The `reserve` set has been superseded by the `object` set in each
  project.

* Added the `update` command for changing `object` attributes.

* Added the `create fund` and `show funds` commands.

* Added the `show sets in project` command.

* The project property `locations` has been removed.

* Added the `archive project` command, to be used instead of `drop
  project`.

* The `drop project` command now only drops archived projects.

* Added the `show projects archived` command.

# v0.0.25

* In `alter project`:

  - Name values used as identifiers are no longer enclosed in
    quotation marks.

  - Values of the `action` property are now restricted to preset names
    (listed in the documentation).

  - The property `locations` has been superseded by new properties
    `origins` and `destinations`, and will be removed in the future.

  - Added the action `drop all`.

  - An error is no longer returned when adding a subvalue to a
    composite property that already contains the subvalue.

* Added the `drop project` command.

* In `select`, added support for `like` and `ilike` pattern matching
  operators.

# v0.0.24

* Added `alter project` command.

# v0.0.23

* Added `create project` command.

# v0.0.22

* Added support for count function.

# v0.0.21

* Added prop.Prop for structured properties.

# v0.0.20

* Added support for projects.

* Added `show projects` and `show project` commands.

* Added `create user` command.

* Added `show users` command.

* Added user authentication.

* The `limit` clause is no longer required with `select`.  Result sets
  larger than 10000 records per `select` return an error.

# v0.0.19

* Upgraded to Go 1.26.

# v0.0.18

* Added `delete` command.

* Added `drop set` command.

* Abstracted client interface to minimize breaking changes.

# v0.0.17

* Breaking change:  Commands may be combined into a single request,
  separated by semicolons.  For this reason, `ccms.Response` now
  contains a slice of results that correspond to each command.

* Added support for `offset` in the `select` command.

# v0.0.16

* Breaking change:  Data rows may contain both `string` and `int64`
  types.  The `Values` field in `ccms.DataRow` now has type `[]any`.

* Attribute data types are provided by the `Type` field in
  `ccms.FieldDescription`.  `Type` can be `"text"` (`string`) or
  `"bigint"` (`int64`).

* Added support for Boolean expressions in the `where` clause of
  `select` and `insert` commands.

* Added support for `order by` in the `select` command.

