package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// TokenNode holds the schema for one vertex of a refresh-token family graph:
// either a refresh-token lineage node or an access-token revocation record.
type TokenNode struct {
	ent.Schema
}

// Fields of the TokenNode.
func (TokenNode) Fields() []ent.Field {
	return []ent.Field{
		field.Text("id").
			SchemaType(textSchema).
			NotEmpty().
			Unique(),
		field.Text("family_id").
			SchemaType(textSchema).
			NotEmpty(),
		field.Text("parent_id").
			SchemaType(textSchema).
			Default(""),
		field.Text("kind").
			SchemaType(textSchema).
			NotEmpty(),
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
		// Access-token nodes carry the JWT expiry so GC can drop them; nil on
		// refresh nodes.
		field.Time("expires_at").
			SchemaType(timeSchema).
			Nillable().
			Optional(),
		field.Time("revoked_at").
			SchemaType(timeSchema).
			Nillable().
			Optional(),
	}
}

// Edges of the TokenNode.
func (TokenNode) Edges() []ent.Edge {
	return []ent.Edge{}
}

// Indexes of the TokenNode.
func (TokenNode) Indexes() []ent.Index {
	return []ent.Index{
		// Family revocation sweep: list every node of a family.
		index.Fields("family_id"),
		// Garbage collection: find expired access nodes.
		index.Fields("expires_at"),
	}
}
