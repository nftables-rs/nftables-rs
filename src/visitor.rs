use serde::{de, Deserialize};
use std::{borrow::Cow, collections::HashSet, fmt::Formatter, marker::PhantomData, str::FromStr};

use crate::stmt::LogFlag;

type CowCowStrs = Cow<'static, [Cow<'static, str>]>;

/// Deserialize null, a string, or string sequence into an `Option<Cow<'static, [Cow<'static, str>]>>`.
pub fn single_string_to_option_vec<'de, D>(
    deserializer: D,
) -> Result<Option<CowCowStrs>, D::Error>
where
    D: de::Deserializer<'de>,
{
    match single_string_to_vec::<'de, D>(deserializer) {
        Ok(value) => match value.len() {
            0 => Ok(None),
            _ => Ok(Some(value)),
        },
        Err(err) => Err(err),
    }
}

/// Deserialize null, a string or string sequence into a `Cow<'static, [Cow<'static, str>]>`.
pub fn single_string_to_vec<'de, D>(
    deserializer: D,
) -> Result<CowCowStrs, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct StringOrVec(PhantomData<CowCowStrs>);
    impl<'de> de::Visitor<'de> for StringOrVec {
        type Value = CowCowStrs;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            formatter.write_str("single string or list of strings")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Cow::Borrowed(&[][..]))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Cow::Owned(vec![Cow::Owned(value.to_owned())]))
        }

        fn visit_seq<S>(self, visitor: S) -> Result<Self::Value, S::Error>
        where
            S: de::SeqAccess<'de>,
        {
            Deserialize::deserialize(de::value::SeqAccessDeserializer::new(visitor))
        }
    }

    deserializer.deserialize_any(StringOrVec(PhantomData))
}

/// Deserialize null, a string or string sequence into an `Option<HashSet<LogFlag>>`.
pub fn single_string_to_option_hashset_logflag<'de, D>(
    deserializer: D,
) -> Result<Option<HashSet<LogFlag>>, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct LogFlagSet(PhantomData<Option<HashSet<LogFlag>>>);
    impl<'de> de::Visitor<'de> for LogFlagSet {
        type Value = Option<HashSet<LogFlag>>;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            formatter.write_str("single string or list of strings")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let mut h: HashSet<LogFlag> = HashSet::new();
            h.insert(LogFlag::from_str(value).unwrap());
            Ok(Some(h))
        }

        fn visit_seq<S>(self, visitor: S) -> Result<Self::Value, S::Error>
        where
            S: de::SeqAccess<'de>,
        {
            Deserialize::deserialize(de::value::SeqAccessDeserializer::new(visitor))
        }
    }
    deserializer.deserialize_any(LogFlagSet(PhantomData))
}
