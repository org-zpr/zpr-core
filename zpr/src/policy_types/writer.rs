use crate::policy::v1;
use crate::policy_types::attribute::Attribute;

/// A trait for writing to a builder type. This is the pattern used to write Cap'n Proto messages.
pub trait WriteTo<Bldr> {
    fn write_to(&self, bldr: &mut Bldr);
}

/// Helper to write attributes into capnp AttrExpr list.
/// We have to do this for client conditions and service conditions.
pub fn write_attributes(
    attrs: &[Attribute],
    conds: &mut capnp::struct_list::Builder<'_, v1::attr_expr::Owned>,
) {
    for (j, attr) in attrs.iter().enumerate() {
        let mut ccond = conds.reborrow().get(j as u32);
        // foo:fee    (foo, eq, fee)
        // foo:       (foo, has, "")
        ccond.set_key(&attr.zpl_key());
        let vals = attr.zpl_values();

        if vals.is_empty() || vals[0].is_empty() || attr.is_multi_valued() {
            ccond.set_op(v1::AttrOp::Has);
        } else {
            ccond.set_op(v1::AttrOp::Eq);
        }
        let mut cvals = ccond.init_value(vals.len() as u32);
        for (i, val) in vals.iter().enumerate() {
            cvals.set(i as u32, val);
        }
    }
}
