//! Miscellaneous utility items.

/// Utility macro to count the number of items in the body.
macro_rules! count {
    {} => (0usize);
    { $b:block $($bs:tt)* } => (1usize + $crate::util::count!($($bs)*));
}

pub(crate) use count;

/// Round-robin-based fairness.
///
/// The first argument is a "fairness counter".  The remaining arguments
/// are code blocks which will all be executed once, but in varying order.
///
/// The order of execution of the code blocks is determined by the fairness
/// counter, such that differing values of the counter result in different
/// orders of execution.  The invoker must increment or randomly generate
/// the fairness counter for each invocation.
macro_rules! fair {
    ( $counter:expr, $($branch:block),+ $(,)? ) => {
        let cohort = $crate::util::count!($({$branch})*);

        for round in 0..2 {
            let mut index = 0;

            $(
                if ((($counter % cohort) <= index) as usize ^ round) != 0 {
                    $branch
                }

                index += 1;
            )+

            let _ = index;
        }
    }
}

pub(crate) use fair;

#[cfg(test)]
mod tests {
    #[test]
    fn single_branch() {
        // Confirm that a single branch always gets executed.

        for i in 0..4 {
            let mut foo = 0;
            fair!(i, { foo += 1 });
            assert_eq!(foo, 1);
        }
    }

    #[test]
    fn multiple_branches() {
        // Confirm that multiple branches always get executed.

        for i in 0..16 {
            let mut foo = 0;
            let mut bar = 0;
            let mut baz = 0;
            let mut quux = 0;

            fair!(i, { foo += 1 }, { bar += 1 }, { baz += 1 }, { quux += 1 },);

            assert_eq!(foo, 1);
            assert_eq!(bar, 1);
            assert_eq!(baz, 1);
            assert_eq!(quux, 1);
        }
    }

    #[test]
    fn fairness() {
        // Confirm that each of several branches regularly gets to go first.
        // (This is a very simplistic and strict check but it captures our current behavior.)

        let mut foo = 0;
        let mut bar = 0;
        let mut baz = 0;
        let mut quux = 0;

        for i in 0..16 {
            let mut token = true;

            fair!(
                i,
                {
                    if token {
                        foo += 1;
                        token = false;
                    }
                },
                {
                    if token {
                        bar += 1;
                        token = false;
                    }
                },
                {
                    if token {
                        baz += 1;
                        token = false;
                    }
                },
                {
                    if token {
                        quux += 1;
                        token = false;
                    }
                },
            );

            assert_eq!(token, false);
        }

        assert_eq!(foo, 4);
        assert_eq!(bar, 4);
        assert_eq!(baz, 4);
        assert_eq!(quux, 4);
    }
}
