# v0.0.18

* Added `delete` command.  See also:
  https://d1f3dtrg62pav.cloudfront.net/ccms/doc/current/#_delete

* Added `drop set` command.  See also:
  https://d1f3dtrg62pav.cloudfront.net/ccms/doc/current/#_drop_set

* Abstracted client interface to minimize breaking changes.
  See also: https://pkg.go.dev/github.com/indexdata/ccms

# v0.0.17

* Breaking change:  Commands may be combined into a single request,
  separated by semicolons.  For this reason, `ccms.Response` now
  contains a slice of results that correspond to each command.

* Added support for `offset` in the `select` command.  See also:
  https://d1f3dtrg62pav.cloudfront.net/ccms/doc/current/#_select

# v0.0.16

* Breaking change:  Data rows may contain both `string` and `int64`
  types.  The `Values` field in `ccms.DataRow` now has type `[]any`.

* Attribute data types are provided by the `Type` field in
  `ccms.FieldDescription`.  `Type` can be `"text"` (`string`) or
  `"bigint"` (`int64`).

* Added support for Boolean expressions in the `where` clause of
  `select` and `insert` commands.  See also:
  https://d1f3dtrg62pav.cloudfront.net/ccms/doc/current/#_queries

* Added support for `order by` in the `select` command.  See also:
  https://d1f3dtrg62pav.cloudfront.net/ccms/doc/current/#_select

