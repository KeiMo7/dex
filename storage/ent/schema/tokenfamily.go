package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// TokenFamily holds the schema for a refresh-token family root. One row per
// family; a non-null revoked_at means the whole family graph is dead.
type TokenFamily struct {
	ent.Schema
}

// Fields of the TokenFamily.
func (TokenFamily) Fields() []ent.Field {
	return []ent.Field{
		field.Text("id").
			SchemaType(textSchema).
			NotEmpty().
			Unique(),
		field.Text("client_id").
			SchemaType(textSchema).
			NotEmpty(),
		field.Text("user_id").
			SchemaType(textSchema).
			NotEmpty(),
		field.Text("connector_id").
			SchemaType(textSchema).
			NotEmpty(),
		field.Time("created_at").
			SchemaType(timeSchema).
			Default(time.Now),
		field.Time("revoked_at").
			SchemaType(timeSchema).
			Nillable().
			Optional(),
		field.Text("revoke_reason").
			SchemaType(textSchema).
			Default(""),
		field.Text("last_replayed_token").
			SchemaType(textSchema).
			Default(""),
	}
}

// Edges of the TokenFamily.
func (TokenFamily) Edges() []ent.Edge {
	return []ent.Edge{}
}

// Indexes of the TokenFamily.
func (TokenFamily) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "connector_id"),
	}
}
